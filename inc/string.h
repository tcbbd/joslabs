#ifndef JOS_INC_STRING_H
#define JOS_INC_STRING_H

#include <inc/types.h>

int	strlen(const char *s) __attribute__((section(".lib")));
int	strnlen(const char *s, size_t size) __attribute__((section(".lib")));
char *	strcpy(char *dst, const char *src) __attribute__((section(".lib")));
char *	strncpy(char *dst, const char *src, size_t size) __attribute__((section(".lib")));
char *	strcat(char *dst, const char *src) __attribute__((section(".lib")));
size_t	strlcpy(char *dst, const char *src, size_t size) __attribute__((section(".lib")));
int	strcmp(const char *s1, const char *s2) __attribute__((section(".lib")));
int	strncmp(const char *s1, const char *s2, size_t size) __attribute__((section(".lib")));
char *	strchr(const char *s, char c) __attribute__((section(".lib")));
char *	strfind(const char *s, char c) __attribute__((section(".lib")));

void *	memset(void *dst, int c, size_t len) __attribute__((section(".lib")));
/* no memcpy - use memmove instead */
void *	memmove(void *dst, const void *src, size_t len) __attribute__((section(".lib")));
int	memcmp(const void *s1, const void *s2, size_t len) __attribute__((section(".lib")));
void *	memfind(const void *s, int c, size_t len) __attribute__((section(".lib")));

long	strtol(const char *s, char **endptr, int base) __attribute__((section(".lib")));

#endif /* not JOS_INC_STRING_H */
