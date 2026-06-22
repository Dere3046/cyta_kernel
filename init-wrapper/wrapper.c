#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <string.h>

#define CKSU_DIR   "/dev/.cksu"
#define CSUD_SRC   "/csud"
#define CSUD_DST   CKSU_DIR "/csud"
#define KEY_FILE   CKSU_DIR "/.superkey"
#define KO_PATH    "/cksu.ko"

static char params[] = "superkey=CKSU_KEY_PLACEHOLDER_PAD_PAD_PAD_000";

static void copy_file(const char *src, const char *dst, mode_t mode)
{
	char buf[4096];
	ssize_t n;
	int in, out;

	in = open(src, O_RDONLY);
	if (in < 0)
		return;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (out < 0) {
		close(in);
		return;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0)
		write(out, buf, n);
	close(out);
	close(in);
}

static void write_superkey(void)
{
	const char *key = params + 9;
	size_t len = strlen(key);
	int fd;

	if (!len)
		return;
	fd = open(KEY_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return;
	write(fd, key, len);
	close(fd);
}

int main(int argc, char *argv[], char *envp[])
{
	int fd;

	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mkdir(CKSU_DIR, 0700);

	copy_file(CSUD_SRC, CSUD_DST, 0755);
	write_superkey();

	fd = open(KO_PATH, O_RDONLY);
	if (fd >= 0) {
		syscall(__NR_finit_module, fd, params, 0);
		close(fd);
	}

	execve("/init.real", argv, envp);
	return 1;
}
