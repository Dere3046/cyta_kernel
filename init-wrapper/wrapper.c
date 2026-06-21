// SPDX-License-Identifier: GPL-2.0-only
// init_wrapper — PID 1 boot wrapper for CKSU
// Loads lkmloader.ko via init_module syscall, then exec real init
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

static char module_args[256] = "module_path=/cksu.ko module_args=\"superkey=CKSU_KEY_PLACEHOLDER_PAD_PAD_PAD_PAD\"";

int main(int argc, char **argv, char **envp) {
    int fd;
    struct stat st;
    void *buf;

    fd = open("/lkmloader.ko", O_RDONLY);
    if (fd < 0)
        goto exec_init;

    if (fstat(fd, &st) < 0 || st.st_size <= 0) {
        close(fd);
        goto exec_init;
    }

    buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (buf == MAP_FAILED)
        goto exec_init;

    syscall(__NR_init_module, buf, (unsigned long)st.st_size, module_args);
    munmap(buf, st.st_size);

exec_init:
    execve("/init.real", argv, envp);
    execve("/init", argv, envp);
    return 1;
}
