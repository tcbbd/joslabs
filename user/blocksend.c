#include <inc/lib.h>

#define CHILD_NUM 32
#define END_TURN 30

void
umain (int argc, char **argv) {
	envid_t who;
	int i;

	for (i = 0; i < CHILD_NUM; i++)
		if ((who = fork()) == 0) {
			who = thisenv->env_parent_id;
			uint32_t send;
			for(send = 0; ; send++) {
				cprintf("send %d from %x to %x\n", send, sys_getenvid(), who);
				ipc_send(who, send, 0, 0);
				if (send == END_TURN)
					return;
			}
		}

	while (1) {
		uint32_t recv = ipc_recv(&who, 0, 0);
		cprintf("%x got %d from %x\n", sys_getenvid(), recv, who);
	}
}
