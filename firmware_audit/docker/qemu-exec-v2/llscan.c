/* llscan:执行镜像内的 /proc 扫描助手(票 16)。
 *
 * 执行镜像按"形状隔离"剥离了 shell 与全部非后端可执行文件,会话清理与
 * 链身份观测因此不能再走 shell 管道,统一由本二进制承担(直接 argv 调用):
 *
 *   llscan count            匹配 proot/qemu/prooted 的进程数(清理判定)
 *   llscan scan             逐行输出 pid=<pid> exe=<exe> cmd=<cmdline>
 *   llscan kill             对匹配进程连进程组一并 SIGKILL(升级清理)
 *   llscan watch <秒> <文件>  延时后扫描写入文件(docker exec -d 观察者)
 *   llscan cat <文件>         原样输出文件到 stdout(镜像无 cat;读回观察快照)
 *
 * 匹配规则:readlink /proc/<pid>/exe 含 "proot"(含 /tmp/prooted-* 桩)或
 * 以 qemu-arm-static / qemu-mips-static 结尾。自身(getpid)排除。
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAXCMD 4096

/* Small self-contained SHA-256 implementation so the stripped image does not
 * need to retain a hashing utility just to identify a transient prooted-* stub. */
static const uint32_t SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

struct sha256_ctx {
    uint32_t h[8];
    uint8_t block[64];
    size_t used;
    uint64_t total;
};

static uint32_t rotr32(uint32_t value, unsigned int bits) {
    return (value >> bits) | (value << (32 - bits));
}

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24);
    p[1] = (uint8_t)(value >> 16);
    p[2] = (uint8_t)(value >> 8);
    p[3] = (uint8_t)value;
}

static void sha256_block(struct sha256_ctx *ctx, const uint8_t *block) {
    uint32_t w[64];
    for (unsigned int i = 0; i < 16; i++)
        w[i] = load_be32(block + i * 4);
    for (unsigned int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18)
                    ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19)
                    ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
    uint32_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h = ctx->h[7];
    for (unsigned int i = 0; i < 64; i++) {
        uint32_t s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + s1 + ch + SHA_K[i] + w[i];
        uint32_t s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = s0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

static void sha256_init(struct sha256_ctx *ctx) {
    static const uint32_t initial[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    memcpy(ctx->h, initial, sizeof(initial));
    ctx->used = 0;
    ctx->total = 0;
}

static void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->total += len;
    while (len > 0) {
        size_t take = 64 - ctx->used;
        if (take > len)
            take = len;
        memcpy(ctx->block + ctx->used, data, take);
        ctx->used += take;
        data += take;
        len -= take;
        if (ctx->used == 64) {
            sha256_block(ctx, ctx->block);
            ctx->used = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *ctx, uint8_t digest[32]) {
    uint64_t bits = ctx->total * 8;
    uint8_t pad = 0x80;
    sha256_update(ctx, &pad, 1);
    pad = 0;
    while (ctx->used != 56)
        sha256_update(ctx, &pad, 1);
    uint8_t length[8];
    for (unsigned int i = 0; i < 8; i++)
        length[7 - i] = (uint8_t)(bits >> (i * 8));
    sha256_update(ctx, length, sizeof(length));
    for (unsigned int i = 0; i < 8; i++)
        store_be32(digest + i * 4, ctx->h[i]);
}

static int file_identity(const char *path, long long *size, char digest[65]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    uint8_t buffer[65536];
    ssize_t n;
    while ((n = read(fd, buffer, sizeof(buffer))) > 0)
        sha256_update(&ctx, buffer, (size_t)n);
    close(fd);
    if (n < 0)
        return -1;
    uint8_t raw[32];
    sha256_final(&ctx, raw);
    for (unsigned int i = 0; i < 32; i++)
        snprintf(digest + i * 2, 3, "%02x", raw[i]);
    digest[64] = '\0';
    *size = (long long)st.st_size;
    return 0;
}

static int match_exe(const char *exe) {
    if (exe[0] == '\0')
        return 0;
    if (strstr(exe, "/proot") != NULL || strstr(exe, "/prooted-") != NULL)
        return 1;
    const char *base = strrchr(exe, '/');
    base = base ? base + 1 : exe;
    return strcmp(base, "qemu-arm-static") == 0
        || strcmp(base, "qemu-mips-static") == 0;
}

static void read_exe(pid_t pid, char *out, size_t outsz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    ssize_t n = readlink(path, out, outsz - 1);
    if (n < 0)
        n = 0;
    out[n] = '\0';
}

static void read_cmdline(pid_t pid, char *out, size_t outsz) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "rb");
    out[0] = '\0';
    if (f == NULL)
        return;
    size_t used = 0;
    int c;
    while ((c = fgetc(f)) != EOF && used + 2 < outsz) {
        out[used++] = (c == '\0') ? ' ' : (char)c;
    }
    fclose(f);
    if (used > 0 && out[used - 1] == ' ')
        used--;
    out[used] = '\0';
}

static pid_t read_pgid(pid_t pid) {
    char path[64], buf[MAXCMD];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* pgid 是右括号后的第 3 个字段(stat: pid (comm) state ppid pgrp)。 */
    char *close = strrchr(buf, ')');
    if (close == NULL)
        return -1;
    int ppid = 0, pgrp = 0;
    if (sscanf(close + 1, " %*c %d %d", &ppid, &pgrp) != 2)
        return -1;
    return (pid_t)pgrp;
}

/* 遍历 /proc,对每个匹配进程调用 cb;返回匹配数。 */
static int for_each_matched(int (*cb)(pid_t, const char *)) {
    DIR *d = opendir("/proc");
    if (d == NULL)
        return 0;
    int matched = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0]))
            continue;
        pid_t pid = (pid_t)atoi(ent->d_name);
        if (pid == getpid())
            continue;
        char exe[MAXCMD];
        read_exe(pid, exe, sizeof(exe));
        if (!match_exe(exe))
            continue;
        matched++;
        if (cb != NULL && cb(pid, exe) != 0)
            break;
    }
    closedir(d);
    return matched;
}

static int print_scan(pid_t pid, const char *exe) {
    char cmd[MAXCMD];
    long long size = -1;
    char digest[65] = "-";
    read_cmdline(pid, cmd, sizeof(cmd));
    if (strstr(exe, "/prooted-") != NULL)
        (void)file_identity(exe, &size, digest);
    if (size >= 0)
        printf("pid=%d exe=%s size=%lld sha256=%s cmd=%s\n",
               (int)pid, exe, size, digest, cmd);
    else
        printf("pid=%d exe=%s size=- sha256=- cmd=%s\n",
               (int)pid, exe, cmd);
    return 0;
}

static int kill_one(pid_t pid, const char *exe) {
    (void)exe;
    pid_t pgid = read_pgid(pid);
    if (pgid > 1)
        kill(-pgid, SIGKILL);
    kill(pid, SIGKILL);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: llscan count|scan|kill|watch <sec> <file>|cat <file>\n");
        return 2;
    }
    if (strcmp(argv[1], "count") == 0) {
        printf("%d\n", for_each_matched(NULL));
        return 0;
    }
    if (strcmp(argv[1], "scan") == 0) {
        for_each_matched(print_scan);
        return 0;
    }
    if (strcmp(argv[1], "kill") == 0) {
        int n = for_each_matched(kill_one);
        printf("%d\n", n);
        return 0;
    }
    if (strcmp(argv[1], "watch") == 0 && argc == 4) {
        sleep((unsigned int)atoi(argv[2]));
        FILE *out = fopen(argv[3], "w");
        if (out == NULL)
            return 3;
        FILE *saved = stdout;
        stdout = out;
        for_each_matched(print_scan);
        stdout = saved;
        fclose(out);
        return 0;
    }
    if (strcmp(argv[1], "cat") == 0 && argc == 3) {
        FILE *f = fopen(argv[2], "rb");
        if (f == NULL)
            return 3;
        int c;
        while ((c = fgetc(f)) != EOF)
            fputc(c, stdout);
        fclose(f);
        return 0;
    }
    fprintf(stderr, "usage: llscan count|scan|kill|watch <sec> <file>|cat <file>\n");
    return 2;
}
