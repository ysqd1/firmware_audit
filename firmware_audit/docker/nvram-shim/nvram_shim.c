/* nvram_shim — /dev/nvram 内核驱动后端的用户态适配桩(票 18)。
 *
 * 机制:guest 内 LD_PRELOAD 拦截 open/openat/read/close 四个符号,把固件库
 * (票 02 核实的 Broadcom 风格 libnvram 系:target/6 libnvram.so、target/7
 * libnvram.so + libCfm.so bcm_nvram_*)对 /dev/nvram 字符设备的访问重定向到
 * 只读模板映像文件。固件库自身代码原样执行——本桩只补齐缺失的内核驱动后端,
 * 不定义、不替换任何 nvram 或 bcm_nvram 导出符号,真实库兼容性由此保持。
 *
 * 驱动协议出处(票 02 反汇编,三方一致):
 *   init: open("/dev/nvram", O_RDWR) 成功 → mmap(NULL,0x10000,PROT_READ,
 *         MAP_SHARED, fd, 0) 存全局 nvram_buf;mmap 落在重定向后的真实
 *         文件 fd 上,无需拦截。
 *   get:  strcpy(buf,name); ret = read(fd, buf, strlen(name)+1);
 *         ret==4 → 返回 nvram_buf + *(uint32*)buf(条目在映像内的字节偏移);
 *         ret≠4(含 0)→ NULL(固件缺失键语义)。
 * 映像格式与 getall 一致:"k=v\0" 串表(票 02 消费侧印证)。
 *
 * 支持表边界(票 18 AC,依据票 02 支持表草案):
 *   - 只覆盖读取:键查询按协议形状判定(read(fd,name,strlen+1) 才是键查询;
 *     getall/show 等输出缓冲 read 形状不符,按缺失键语义返回 0 且不写日志、
 *     不改写缓冲——复审 P-c2);未声明键 read 返回 0 + 键名追加到未决日志,
 *     不伪造值;
 *   - 写不支持:重定向 fd 强制只读,write 返回 EBADF → set/unset/commit
 *     由真实库代码如实失败;
 *   - nvram_getall 不在支持表:其 read 非键查询形状,得 0 后库按 ret!=len
 *     如实判失败,模板值不整表泄漏;
 *   - envram(MTD)系不经本桩(不拦其 MTD 路径),对着缺失 MTD 如实失败。
 *
 * 实现约束:-nostdlib 纯内联 svc syscall(ARM EABI:调用号 r7,svc 0),
 * 零外部符号依赖,规避 uClibc ldso 对 preload 库未决重定位的次序问题;
 * 路径固定(会话工具挂载形状的单一出处):映像 /session/adapt/nvram.img,
 * 未决日志 /tmp/nvram-unresolved.log(会话运行目录,宿主侧可读回)。
 */
typedef unsigned int u32;

#define SYS_read   3
#define SYS_write  4
#define SYS_close  6
#define SYS_openat 322

#define AT_FDCWD  -100
#define O_RDONLY   0
#define O_WRONLY   1
#define O_ACCMODE  3
#define O_CREAT  0100
#define O_APPEND 02000

#define NVRAM_DEVICE_PATH  "/dev/nvram"
#define NVRAM_IMAGE_PATH   "/session/adapt/nvram.img"
#define NVRAM_UNRESOLVED   "/tmp/nvram-unresolved.log"

#define IMAGE_CAP    65536
#define MAX_ENTRIES  512
#define MAX_TRACKED  64

static long sys4(long nr, long a, long b, long c, long d) {
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    register long r2 __asm__("r2") = c;
    register long r3 __asm__("r3") = d;
    register long r7 __asm__("r7") = nr;
    __asm__ volatile("svc 0"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), "r"(r3), "r"(r7)
                     : "memory");
    return r0;
}

static long sys3(long nr, long a, long b, long c) {
    return sys4(nr, a, b, c, 0);
}

static unsigned long slen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

static int seq_eq(const char *a, unsigned long alen, const char *b) {
    unsigned long i;
    for (i = 0; i < alen; i++) {
        if (a[i] != b[i]) return 0;
    }
    return b[alen] == '\0';
}

/* ---- 被 track 的 fd 表(原子锁;线程目标下表操作极短) ----
 * 锁用内联 ldrex/strex(ARMv6+;qemu 用户态正常执行),不能用 __sync 内建:
 * 它们在 -O2 下会生成对 libgcc 的未决调用,uClibc 预加载环境无法解析,
 * 会导致整个桩被 ldso 静默忽略(票 18 实测)。同理禁用栈保护与循环模式
 * 识别(后者会把扫描循环改写为 strlen 调用)。 */

static volatile int g_lock;
static int g_fds[MAX_TRACKED];

static void table_lock(void) {
    unsigned int tmp;
    asm volatile(
        "1: ldrex %0, [%2]\n"
        "   teq %0, #0\n"
        "   strexeq %0, %1, [%2]\n"
        "   teq %0, #0\n"
        "   bne 1b\n"
        : "=&r"(tmp)
        : "r"(1), "r"(&g_lock)
        : "cc", "memory");
}

static void table_unlock(void) {
    asm volatile("str %1, [%0]"
                 :
                 : "r"(&g_lock), "r"(0)
                 : "memory");
}

static int table_track(int fd) {
    /* 返回 0 = 已登记;-1 = 表满(登记失败)——调用方让本次重定向 open
     * 直接失败,而不是让后续 read 静默穿透到映像原始字节(评审 nit)。 */
    int i;
    int slot = -1;
    table_lock();
    for (i = 0; i < MAX_TRACKED; i++) {
        if (g_fds[i] == 0) {
            g_fds[i] = fd;
            slot = 0;
            break;
        }
    }
    table_unlock();
    return slot;
}

static void table_untrack(int fd) {
    int i;
    table_lock();
    for (i = 0; i < MAX_TRACKED; i++) {
        if (g_fds[i] == fd) {
            g_fds[i] = 0;
            break;
        }
    }
    table_unlock();
}

static int table_tracked(int fd) {
    int i;
    int hit = 0;
    table_lock();
    for (i = 0; i < MAX_TRACKED; i++) {
        if (g_fds[i] == fd) {
            hit = 1;
            break;
        }
    }
    table_unlock();
    return hit;
}

/* ---- 模板映像加载与键索引 ---- */

static unsigned char g_image[IMAGE_CAP];
static unsigned long g_image_len;
/* 每条目:名字在映像内偏移、名字长度、条目起始偏移(即驱动协议返回值)。 */
static unsigned long g_name_off[MAX_ENTRIES];
static unsigned int g_name_len[MAX_ENTRIES];
static unsigned long g_entry_off[MAX_ENTRIES];
static unsigned long g_entry_count;
static int g_loaded;

static void load_image(void) {
    long fd;
    unsigned long total = 0;
    unsigned long i = 0;
    if (g_loaded) return;
    /* 置位、装载都在锁内:多线程目标下两个 read 可同时首发,裸
     * check-then-set 会交叉写映像缓冲与索引(票 18 评审 nit) */
    table_lock();
    if (g_loaded) {
        table_unlock();
        return;
    }
    g_loaded = 1; /* 打开失败保持空表(全部按未决键处理),不重试 */
    fd = sys4(SYS_openat, AT_FDCWD, (long)NVRAM_IMAGE_PATH, O_RDONLY, 0);
    if (fd < 0) {
        table_unlock();
        return;
    }
    for (;;) {
        long n = sys3(SYS_read, fd, (long)(g_image + total),
                      (long)(IMAGE_CAP - total));
        if (n <= 0) break;
        total += (unsigned long)n;
        if (total >= IMAGE_CAP) break;
    }
    sys3(SYS_close, fd, 0, 0);
    g_image_len = total;
    while (i < total && g_entry_count < MAX_ENTRIES) {
        unsigned long start = i;
        unsigned long eq = 0;
        int has_eq = 0;
        while (i < total && g_image[i] != '\0') {
            if (g_image[i] == '=' && !has_eq) {
                has_eq = 1;
                eq = i;
            }
            i++;
        }
        if (i >= total) break;
        if (has_eq && eq > start) {
            g_name_off[g_entry_count] = start;
            g_name_len[g_entry_count] = (unsigned int)(eq - start);
            g_entry_off[g_entry_count] = start;
            g_entry_count++;
        }
        i++; /* 越过条目终止 NUL;连续空段自然跳过 */
    }
    table_unlock();
}

static long lookup_offset(const char *name, unsigned long len) {
    unsigned long i;
    for (i = 0; i < g_entry_count; i++) {
        if (g_name_len[i] == len &&
            seq_eq((const char *)(g_image + g_name_off[i]), len, name)) {
            return (long)g_entry_off[i];
        }
    }
    return -1;
}

static void log_unresolved(const char *name, unsigned long len) {
    long fd = sys4(SYS_openat, AT_FDCWD, (long)NVRAM_UNRESOLVED,
                   O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) return;
    sys3(SYS_write, fd, (long)name, (long)len);
    sys3(SYS_write, fd, (long)"\n", 1);
    sys3(SYS_close, fd, 0, 0);
}

/* ---- 拦截的 libc 符号 ---- */

static int is_nvram_path(const char *path) {
    unsigned long i;
    unsigned long n = slen(NVRAM_DEVICE_PATH);
    if (path == 0 || slen(path) != n) return 0;
    for (i = 0; i < n; i++) {
        if (path[i] != NVRAM_DEVICE_PATH[i]) return 0;
    }
    return 1;
}

static int open_common(const char *path, int flags, int mode) {
    if (is_nvram_path(path)) {
        /* 先判定再打开:对 /dev/nvram 不执行真实 open(固件根内不存在,
         * 会先得到 ENOENT),直接重定向到只读模板映像;写路径(set/unset/
         * commit)由此在真实库代码里如实失败,而不是伪造成功。 */
        long img = sys4(SYS_openat, AT_FDCWD, (long)NVRAM_IMAGE_PATH,
                        O_RDONLY, 0);
        if (img >= 0 && table_track((int)img) != 0) {
            sys3(SYS_close, img, 0, 0);
            return -1;
        }
        return (int)img;
    }
    return (int)sys4(SYS_openat, AT_FDCWD, (long)path, (long)flags, (long)mode);
}

int open(const char *path, int flags, ...) {
    /* 模式参数仅 O_CREAT 时有意义;固件库打开 /dev/nvram 不带 O_CREAT,
     * 其他路径转发时保持调用方语义(变参取第三个整型参数)。 */
    __builtin_va_list ap;
    int mode = 0;
    __builtin_va_start(ap, flags);
    if (flags & O_CREAT) mode = __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    return open_common(path, flags, mode);
}

int open64(const char *path, int flags, ...) {
    __builtin_va_list ap;
    int mode = 0;
    __builtin_va_start(ap, flags);
    if (flags & O_CREAT) mode = __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    return open_common(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...) {
    __builtin_va_list ap;
    int mode = 0;
    long fd;
    __builtin_va_start(ap, flags);
    if (flags & O_CREAT) mode = __builtin_va_arg(ap, int);
    __builtin_va_end(ap);
    if (dirfd == AT_FDCWD && is_nvram_path(path)) {
        return open_common(path, flags, mode);
    }
    fd = sys4(SYS_openat, (long)dirfd, (long)path, (long)flags, (long)mode);
    return (int)fd;
}

long read(int fd, void *buf, unsigned long count) {
    if (table_tracked(fd)) {
        char *p = (char *)buf;
        unsigned long len = 0;
        long off;
        load_image();
        if (count == 0) return 0;
        /* 键查询判定(票 02 协议形状):合法键查询是 read(fd,name,strlen+1),
         * 缓冲内含名字与终止 NUL。形状不符(getall/show 的输出缓冲等)不是
         * 键查询:按缺失键语义返回 0(库按 ret!=len 如实判失败),不把缓冲
         * 内容当键名写未决日志,也不改写调用方缓冲(复审 P-c2)。 */
        while (len < count && p[len] != '\0') len++;
        if (len == 0 || len + 1 != count) return 0;
        off = lookup_offset(p, len);
        if (off < 0) {
            log_unresolved(p, len);
            return 0; /* 固件缺失键语义:ret≠4 → 库返回 NULL */
        }
        if (count < 4) return 0; /* 调用方缓冲不足,按缺失键语义处理 */
        u32 v = (u32)off;
        p[0] = (char)(v & 0xff);
        p[1] = (char)((v >> 8) & 0xff);
        p[2] = (char)((v >> 16) & 0xff);
        p[3] = (char)((v >> 24) & 0xff);
        return 4;
    }
    return sys3(SYS_read, (long)fd, (long)buf, (long)count);
}

int close(int fd) {
    table_untrack(fd);
    return (int)sys3(SYS_close, (long)fd, 0, 0);
}
