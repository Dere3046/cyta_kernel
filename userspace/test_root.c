// SPDX-License-Identifier: GPL-2.0-only
/*
 * test_root.c — trigger CKSU root elevation via root key
 *
 * Copyright (C) 2026 dere3046
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
