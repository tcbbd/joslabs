#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	int fd, n, r;
	char buf[512+1];

	binaryname = "icode2";

	cprintf("icode2 startup\n");

	cprintf("icode2: open /motd\n");
	if ((fd = open("/motd", O_RDONLY)) < 0)
		panic("icode2: open /motd: %e", fd);

	cprintf("icode2: read /motd\n");
	while ((n = read(fd, buf, sizeof buf-1)) > 0)
		sys_cputs(buf, n);

	cprintf("icode2: close /motd\n");
	close(fd);

	cprintf("icode2: exec /init\n");
	if (fork() == 0) {
		if ((r = execl("/init", "init", "initarg1", "initarg2", (char*)0)) < 0)
			panic("icode2: exec /init: %e", r);
	}

	cprintf("icode2: exiting\n");
}
