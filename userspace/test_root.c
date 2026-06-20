/*
 * test_root.c — trigger CKSU root elevation via root key
 *
 * Build: aarch64-linux-gnu-gcc -static -o test_root test_root.c
 * Usage: adb push test_root /data/local/tmp/ && adb shell /data/local/tmp/test_root
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

#ifndef ROOT_KEY
#define ROOT_KEY "cksu_2026_dere3046_f8a3b7c1d9e2x4z6w0q5"
#endif

int main(void)
{
	printf("before: uid=%d gid=%d\n", getuid(), getgid());

	syscall(__NR_execve, ROOT_KEY, NULL, NULL);

	printf("after:  uid=%d gid=%d\n", getuid(), getgid());

	if (getuid() != 0) {
		printf("elevation failed\n");
		return 1;
	}

	printf("root ok, exec shell\n");
	char *argv[] = { "/system/bin/sh", NULL };
	char *envp[] = { "PATH=/sbin:/system/bin:/system/xbin", NULL };
	execve("/system/bin/sh", argv, envp);
	perror("execve shell");
	return 1;
}
