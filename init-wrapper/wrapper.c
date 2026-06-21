// SPDX-License-Identifier: GPL-2.0-only
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static char module_params[128] = "superkey=CKSU_KEY_PLACEHOLDER_PAD_PAD_PAD_000";

int main(int argc, char **argv, char **envp) {
    int fd;
    struct stat st;
    void *buf;

    fd = open("/cksu.ko", O_RDONLY);
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

    syscall(__NR_init_module, buf, (unsigned long)st.st_size, module_params);
    munmap(buf, st.st_size);

exec_init:
    execve("/init.real", argv, envp);
    execve("/init", argv, envp);
    return 1;
}
