// Main public header file for our user-land support library,
// whose code lives in the lib directory.
// This library is roughly our OS's version of a standard C library,
// and is intended to be linked into all user-mode applications
// (NOT the kernel or boot loader).

#ifndef JOS_INC_LIB_H
#define JOS_INC_LIB_H 1

#include <inc/types.h>
#include <inc/stdio.h>
#include <inc/stdarg.h>
#include <inc/string.h>
#include <inc/error.h>
#include <inc/assert.h>
#include <inc/env.h>
#include <inc/memlayout.h>
#include <inc/syscall.h>
#include <inc/trap.h>
#include <inc/fs.h>
#include <inc/fd.h>
#include <inc/args.h>
#include <inc/malloc.h>
#include <inc/ns.h>

#define USED(x)		(void)(x)

// main user program
void	umain(int argc, char **argv);

// libmain.c or entry.S
extern const char *binaryname;
extern const volatile struct Env *thisenv;
extern const volatile struct Env envs[NENV];
extern const volatile struct Page pages[];

// exit.c
void	exit(void) __attribute__((section(".lib")));

// pgfault.c
void	set_pgfault_handler(void (*handler)(struct UTrapframe *utf));

// readline.c
char*	readline(const char *buf);

// syscall.c
void	sys_cputs(const char *string, size_t len) __attribute__((section(".lib")));
int	sys_cgetc(void) __attribute__((section(".lib")));
envid_t	sys_getenvid(void) __attribute__((section(".lib")));
int	sys_env_destroy(envid_t) __attribute__((section(".lib")));

int     sys_map_kernel_page(void* kpage, void* va) __attribute__((section(".lib")));

void	sys_yield(void) __attribute__((section(".lib")));
static envid_t sys_exofork(void);
int	sys_env_set_status(envid_t env, int status) __attribute__((section(".lib")));
int	sys_env_set_trapframe(envid_t env, struct Trapframe *tf) __attribute__((section(".lib")));
int	sys_env_set_pgfault_upcall(envid_t env, void *upcall) __attribute__((section(".lib")));
int	sys_page_alloc(envid_t env, void *pg, int perm) __attribute__((section(".lib")));
int	sys_page_map(envid_t src_env, void *src_pg,
		     envid_t dst_env, void *dst_pg, int perm) __attribute__((section(".lib")));
int	sys_page_unmap(envid_t env, void *pg) __attribute__((section(".lib")));
int	sys_ipc_try_send(envid_t to_env, uint32_t value, void *pg, int perm) __attribute__((section(".lib")));
int	sys_ipc_recv(void *rcv_pg) __attribute__((section(".lib")));
unsigned int sys_time_msec(void) __attribute__((section(".lib")));

// This must be inlined.  Exercise for reader: why?
static __inline envid_t __attribute__((always_inline))
sys_exofork(void)
{
	envid_t ret;
	__asm __volatile("int %2"
		: "=a" (ret)
		: "a" (SYS_exofork),
		  "i" (T_SYSCALL)
	);
	return ret;
}

// ipc.c
void	ipc_send(envid_t to_env, uint32_t value, void *pg, int perm) __attribute__((section(".lib")));
int32_t ipc_recv(envid_t *from_env_store, void *pg, int *perm_store) __attribute__((section(".lib")));
envid_t	ipc_find_env(enum EnvType type) __attribute__((section(".lib")));

// fork.c
#define	PTE_SHARE	0x400
envid_t	fork(void);
envid_t	sfork(void);	// Challenge!

int     sys_map_kernel_page(void* kpage, void* va);

int sys_sbrk(uint32_t inc);

// fd.c
int	close(int fd) __attribute__((section(".lib")));
ssize_t	read(int fd, void *buf, size_t nbytes) __attribute__((section(".lib")));
ssize_t	write(int fd, const void *buf, size_t nbytes) __attribute__((section(".lib")));
int	seek(int fd, off_t offset) __attribute__((section(".lib")));
void	close_all(void) __attribute__((section(".lib")));
ssize_t	readn(int fd, void *buf, size_t nbytes) __attribute__((section(".lib")));
int	dup(int oldfd, int newfd) __attribute__((section(".lib")));
int	fstat(int fd, struct Stat *statbuf) __attribute__((section(".lib")));
int	stat(const char *path, struct Stat *statbuf) __attribute__((section(".lib")));

// file.c
int	open(const char *path, int mode) __attribute__((section(".lib")));
int	ftruncate(int fd, off_t size) __attribute__((section(".lib")));
int	remove(const char *path) __attribute__((section(".lib")));
int	sync(void) __attribute__((section(".lib")));

// pageref.c
int	pageref(void *addr) __attribute__((section(".lib")));

// sockets.c
int     accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int     bind(int s, struct sockaddr *name, socklen_t namelen);
int     shutdown(int s, int how);
int     connect(int s, const struct sockaddr *name, socklen_t namelen);
int     listen(int s, int backlog);
int     socket(int domain, int type, int protocol);

// nsipc.c
int     nsipc_accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int     nsipc_bind(int s, struct sockaddr *name, socklen_t namelen);
int     nsipc_shutdown(int s, int how);
int     nsipc_close(int s);
int     nsipc_connect(int s, const struct sockaddr *name, socklen_t namelen);
int     nsipc_listen(int s, int backlog);
int     nsipc_recv(int s, void *mem, int len, unsigned int flags);
int     nsipc_send(int s, const void *buf, int size, unsigned int flags);
int     nsipc_socket(int domain, int type, int protocol);

// spawn.c
envid_t	spawn(const char *program, const char **argv);
envid_t	spawnl(const char *program, const char *arg0, ...);

// exec.c
int execv(const char *program, const char **argv) __attribute__((section(".lib")));
int execl(const char *program, const char *arg0, ...) __attribute__((section(".lib")));


/* File open modes */
#define	O_RDONLY	0x0000		/* open for reading only */
#define	O_WRONLY	0x0001		/* open for writing only */
#define	O_RDWR		0x0002		/* open for reading and writing */
#define	O_ACCMODE	0x0003		/* mask for above modes */

#define	O_CREAT		0x0100		/* create if nonexistent */
#define	O_TRUNC		0x0200		/* truncate to zero length */
#define	O_EXCL		0x0400		/* error if already exists */
#define O_MKDIR		0x0800		/* create directory, not regular file */

#endif	// !JOS_INC_LIB_H
