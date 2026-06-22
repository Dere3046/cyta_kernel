#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

static char params[] = "superkey=CKSU_KEY_PLACEHOLDER_PAD_PAD_PAD_000";

int main(int argc, char *argv[], char *envp[])
{
	int fd = open("/cksu.ko", O_RDONLY);
	if (fd >= 0) {
		syscall(__NR_finit_module, fd, params, 0);
		close(fd);
	}
	execve("/init.real", argv, envp);
	return 1;
}
