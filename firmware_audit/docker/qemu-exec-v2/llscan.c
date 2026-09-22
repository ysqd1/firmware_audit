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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXCMD 4096

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
    read_cmdline(pid, cmd, sizeof(cmd));
    printf("pid=%d exe=%s cmd=%s\n", (int)pid, exe, cmd);
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
