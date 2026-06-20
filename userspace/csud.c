// SPDX-License-Identifier: GPL-2.0-only
/*
 * csud.c — CKSU userspace driver
 *
 * Copyright (C) 2026 dere3046
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "libcksu.h"

static const char *g_key;

static void usage(void)
{
	fprintf(stderr,
		"csud -k <superkey> <command> [args...]\n"
		"\n"
		"  hello              check module loaded\n"
		"  root               grant root, exec shell\n"
		"  su [cmd...]        grant root, exec cmd\n"
		"  allow <uid>        add uid to allowlist\n"
		"  deny <uid>         remove uid\n"
		"  list               show allowlist\n"
		"  test               run test suite\n"
	);
}

static int cmd_hello(void)
{
	long ver = cksu_hello();
	if (ver < 0) {
		printf("FAIL: cksu not loaded (%ld)\n", ver);
		return 1;
	}
	printf("cksu v%ld.%ld\n", (ver >> 8) & 0xFF, ver & 0xFF);
	return 0;
}

static int cmd_root(void)
{
	long ret = cksu_grant_root(g_key);
	if (ret) {
		printf("FAIL: grant_root=%ld\n", ret);
		return 1;
	}
	printf("uid=%d gid=%d\n", getuid(), getgid());
	char *argv[] = {"/system/bin/sh", NULL};
	char *envp[] = {"PATH=/sbin:/system/bin:/system/xbin", NULL};
	execve("/system/bin/sh", argv, envp);
	perror("execve");
	return 1;
}

static int cmd_su(int argc, char **argv)
{
	long ret = cksu_grant_root(g_key);
	if (ret) {
		printf("FAIL: grant_root=%ld\n", ret);
		return 1;
	}
	if (argc > 0) {
		execvp(argv[0], argv);
		perror("execvp");
		return 1;
	}
	char *sh[] = {"/system/bin/sh", NULL};
	char *envp[] = {"PATH=/sbin:/system/bin:/system/xbin", NULL};
	execve("/system/bin/sh", sh, envp);
	perror("execve");
	return 1;
}

static int cmd_allow(const char *uid_str)
{
	uid_t uid = atoi(uid_str);
	long ret = cksu_add_uid(g_key, uid);
	if (ret)
		printf("FAIL: %ld\n", ret);
	else
		printf("added %d\n", uid);
	return ret ? 1 : 0;
}

static int cmd_deny(const char *uid_str)
{
	uid_t uid = atoi(uid_str);
	long ret = cksu_remove_uid(g_key, uid);
	if (ret)
		printf("FAIL: %ld\n", ret);
	else
		printf("removed %d\n", uid);
	return ret ? 1 : 0;
}

static int cmd_list(void)
{
	uid_t buf[256];
	long n = cksu_get_list(g_key, buf, 256);
	if (n < 0) {
		printf("FAIL: %ld\n", n);
		return 1;
	}
	printf("allowlist (%ld):\n", n);
	for (long i = 0; i < n; i++)
		printf("  %d\n", buf[i]);
	return 0;
}

static int test_hello(void)
{
	long ver = cksu_hello();
	if (ver <= 0) return 1;
	printf("  version=0x%04lx\n", ver);
	return 0;
}

static int test_challenge(void)
{
	uint8_t nonce[32];
	long ret = cksu_get_challenge(nonce);
	if (ret) return 1;
	int zeros = 0;
	for (int i = 0; i < 32; i++)
		if (!nonce[i]) zeros++;
	if (zeros == 32) return 1;
	return 0;
}

static int test_auth(void)
{
	long ret = cksu_grant_root(g_key);
	return ret ? 1 : 0;
}

static int test_root(void)
{
	long ret = cksu_grant_root(g_key);
	if (ret) return 1;
	if (getuid() != 0) return 1;
	if (getgid() != 0) return 1;
	return 0;
}

static int test_allowlist(void)
{
	long ret;
	ret = cksu_add_uid(g_key, 99999);
	if (ret) return 1;

	uid_t buf[256];
	long n = cksu_get_list(g_key, buf, 256);
	if (n < 0) return 1;

	int found = 0;
	for (long i = 0; i < n; i++)
		if (buf[i] == 99999) found = 1;
	if (!found) return 1;

	ret = cksu_remove_uid(g_key, 99999);
	return ret ? 1 : 0;
}

static int test_su_compat(void)
{
	uid_t uid = getuid();
	cksu_add_uid(g_key, uid);

	int r = access("/system/bin/su", F_OK);
	cksu_remove_uid(g_key, uid);

	return (r == 0) ? 0 : 1;
}

static int test_selinux(void)
{
	FILE *f = fopen("/data/data/", "r");
	if (!f) return 1;
	fclose(f);
	return 0;
}

static int cmd_test(void)
{
	struct {
		const char *name;
		int (*fn)(void);
	} tests[] = {
		{"hello", test_hello},
		{"challenge", test_challenge},
		{"auth", test_auth},
		{"root", test_root},
		{"allowlist", test_allowlist},
		{"su_compat", test_su_compat},
		{"selinux", test_selinux},
	};
	int total = sizeof(tests) / sizeof(tests[0]);
	int pass = 0;

	printf("[cksu] test suite\n\n");

	for (int i = 0; i < total; i++) {
		int r = tests[i].fn();
		printf("[%d/%d] %-14s %s\n", i + 1, total,
		       tests[i].name, r ? "FAIL" : "OK");
		if (!r) pass++;
	}

	printf("\n%s: %d/%d\n", pass == total ? "PASS" : "FAIL", pass, total);
	return pass == total ? 0 : 1;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage();
		return 1;
	}

	int argi = 1;

	if (strcmp(argv[argi], "-k") == 0) {
		if (argi + 1 >= argc) {
			usage();
			return 1;
		}
		g_key = argv[argi + 1];
		argi += 2;
	} else {
		g_key = getenv("CKSU_KEY");
		if (!g_key) {
			fprintf(stderr, "error: set CKSU_KEY or use -k <key>\n");
			return 1;
		}
	}

	if (argi >= argc) {
		usage();
		return 1;
	}

	const char *cmd = argv[argi];

	if (strcmp(cmd, "hello") == 0) return cmd_hello();
	if (strcmp(cmd, "root") == 0) return cmd_root();
	if (strcmp(cmd, "su") == 0) return cmd_su(argc - argi - 1, argv + argi + 1);
	if (strcmp(cmd, "allow") == 0) {
		if (argi + 1 >= argc) { usage(); return 1; }
		return cmd_allow(argv[argi + 1]);
	}
	if (strcmp(cmd, "deny") == 0) {
		if (argi + 1 >= argc) { usage(); return 1; }
		return cmd_deny(argv[argi + 1]);
	}
	if (strcmp(cmd, "list") == 0) return cmd_list();
	if (strcmp(cmd, "test") == 0) return cmd_test();

	fprintf(stderr, "unknown command: %s\n", cmd);
	return 1;
}
