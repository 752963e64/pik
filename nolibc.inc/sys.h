/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * Syscall definitions for NOLIBC (those in man(2))
 * Copyright (C) 2017-2021 Willy Tarreau <w@1wt.eu>
 * -----------------------------------------------
 * change syscall handling & adds missing ones.
 * Copyright (C) 2023 HackIT <752963e64@tutanota.com>
 */

#ifndef _NOLIBC_SYS_H
#define _NOLIBC_SYS_H

#include <stdarg.h>
#include "stdint.h"

/* system includes */
#include <asm/unistd.h>
#include <asm/signal.h>  // for SIGCHLD
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/time.h>

#include "arch.h"
#include "errno.h"
#include "types.h"


/* Functions in this file only describe syscalls. They're declared static so
 * that the compiler usually decides to inline them while still being allowed
 * to pass a pointer to one of their instances. Each syscall exists in two
 * versions:
 *   - the "internal" ones, which matches the raw syscall interface at the
 *     kernel level, which may sometimes slightly differ from the documented
 *     libc-level ones. For example most of them return either a valid value
 *     or -errno. All of these are prefixed with "sys_". They may be called
 *     by non-portable applications if desired.
 *
 *   - the "exported" ones, whose interface must closely match the one
 *     documented in man(2), that applications are supposed to expect. These
 *     ones rely on the internal ones, and set errno.
 *
 * Each syscall will be defined with the two functions, sorted in alphabetical
 * order applied to the exported names.
 *
 * In case of doubt about the relevance of a function here, only those which
 * set errno should be defined here. Wrappers like those appearing in man(3)
 * should not be placed here.
 */


/*
 * int brk(void *addr);
 * void *sbrk(intptr_t inc)
 */

#ifdef __NR_brk
static __attribute__((unused))
void *sys_brk(void *addr)
{
	return (void *)my_syscall1(__NR_brk, addr);
}

static __attribute__((unused))
int brk(void *addr)
{
	void *ret = sys_brk(addr);

	if (!ret) {
		SET_ERRNO(ENOMEM);
		return -1;
	}
	return 0;
}

static __attribute__((unused))
void *sbrk(intptr_t inc)
{
	void *ret;

	/* first call to find current end */
	if ((ret = sys_brk(0)) && (sys_brk(ret + inc) == ret + inc))
		return ret + inc;

	SET_ERRNO(ENOMEM);
	return (void *)-1;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_brk isn't defined, cannot implement sys_brk()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_brk */

/*
 * int chdir(const char *path);
 */

#ifdef __NR_chdir
static __attribute__((unused))
int sys_chdir(const char *path)
{
	return my_syscall1(__NR_chdir, path);
}

static __attribute__((unused))
int chdir(const char *path)
{
	int ret = sys_chdir(path);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_chdir isn't defined, cannot implement sys_chdir()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_chdir */

/*
 * int fchdir(int dfd);
 */

#ifdef __NR_fchdir
static __attribute__((unused))
int sys_fchdir(int dfd)
{
	return my_syscall1(__NR_fchdir, dfd);
}

static __attribute__((unused))
int fchdir(int dfd)
{
	int ret = sys_fchdir(dfd);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_fchdir isn't defined, cannot implement sys_fchdir()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_fchdir */

/*
 * int chmod(const char *path, mode_t mode);
 */

#ifdef __NR_chmod
static __attribute__((unused))
int sys_chmod(const char *path, mode_t mode)
{
	return my_syscall2(__NR_chmod, path, mode);
}

static __attribute__((unused))
int chmod(const char *path, mode_t mode)
{
	int ret = sys_chmod(path, mode);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_chmod isn't defined, cannot implement sys_chmod()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_chmod */

/*
 * int fchmod(int fd, mode_t mode);
 */

#ifdef __NR_fchmod
static __attribute__((unused))
int sys_fchmod(int fd, mode_t mode)
{
	return my_syscall2(__NR_fchmod, fd, mode);
}

static __attribute__((unused))
int fchmod(int fd, mode_t mode)
{
	int ret = sys_fchmod(fd, mode);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_fchmod isn't defined, cannot implement sys_fchmod()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_fchmod */


/*
 * int fchmodat(const char *path, mode_t mode);
 */

#ifdef __NR_fchmodat
static __attribute__((unused))
int sys_fchmodat(int dfd, const char *path, mode_t mode, int flags)
{
	return my_syscall4(__NR_fchmodat, dfd, path, mode, flags);
}

static __attribute__((unused))
int fchmodat(int dfd, const char *path, mode_t mode, int flags)
{
	int ret = sys_fchmodat(dfd, path, mode, flags);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_fchmodat isn't defined, cannot implement sys_fchmodat()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_fchmodat */

/*
 * int chown(const char *path, uid_t owner, gid_t group);
 */

#ifdef __NR_chown
static __attribute__((unused))
int sys_chown(const char *path, uid_t owner, gid_t group)
{
	return my_syscall3(__NR_chown, path, owner, group);
}

static __attribute__((unused))
int chown(const char *path, uid_t owner, gid_t group)
{
	int ret = sys_chown(path, owner, group);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_chown isn't defined, cannot implement sys_chown()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_chown */

/*
 * int fchown(int fd, uid_t owner, gid_t group);
 */

#ifdef __NR_fchown
static __attribute__((unused))
int sys_fchown(int fd, uid_t owner, gid_t group)
{
	return my_syscall3(__NR_fchown, fd, owner, group);
}

static __attribute__((unused))
int fchown(int fd, uid_t owner, gid_t group)
{
	int ret = sys_fchown(fd, owner, group);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_fchown isn't defined, cannot implement sys_fchown()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_fchown */

/*
 * int lchown(const char *path, uid_t owner, gid_t group);
 */

#ifdef __NR_lchown
static __attribute__((unused))
int sys_lchown(const char *path, uid_t owner, gid_t group)
{
	return my_syscall3(__NR_lchown, path, owner, group);
}

static __attribute__((unused))
int lchown(const char *path, uid_t owner, gid_t group)
{
	int ret = sys_lchown(path, owner, group);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_lchown isn't defined, cannot implement sys_lchown()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_lchown */

/*
 * int fchownat(const char *path, uid_t owner, gid_t group);
 */

#ifdef __NR_fchownat
static __attribute__((unused))
int sys_fchownat(int dfd, const char *path, uid_t owner, gid_t group, int flags);
{
	return my_syscall5(__NR_fchownat, dfd, path, owner, group, flags);
}

static __attribute__((unused))
int chown(const char *path, uid_t owner, gid_t group)
{
	int ret = sys_fchownat(path, owner, group);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_fchownat isn't defined, cannot implement sys_fchownat()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_fchownat */


/*
 * int chroot(const char *path);
 */

#ifdef __NR_chroot
static __attribute__((unused))
int sys_chroot(const char *path)
{
	return my_syscall1(__NR_chroot, path);
}

static __attribute__((unused))
int chroot(const char *path)
{
	int ret = sys_chroot(path);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_chroot isn't defined, cannot implement sys_chroot()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_chroot */

/*
 * int close(int fd);
 */

#ifedf __NR_close
static __attribute__((unused))
int sys_close(int fd)
{
	return my_syscall1(__NR_close, fd);
}

static __attribute__((unused))
int close(int fd)
{
	int ret = sys_close(fd);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_close isn't defined, cannot implement sys_close()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_close */

/*
 * int dup(int fd);
 */

#ifdef __NR_dup
static __attribute__((unused))
int sys_dup(int fd)
{
	return my_syscall1(__NR_dup, fd);
}

static __attribute__((unused))
int dup(int fd)
{
	int ret = sys_dup(fd);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_dup isn't defined, cannot implement sys_dup()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_dup */

/*
 * int dup2(int old, int new);
 */

#ifdef __NR_dup2
static __attribute__((unused))
int sys_dup2(int old, int new)
{
	return my_syscall2(__NR_dup2, old, new);
}

static __attribute__((unused))
int dup2(int old, int new)
{
	int ret = sys_dup2(old, new);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_dup2 isn't defined, cannot implement sys_dup2()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_dup2 */

/*
 * int dup3(int old, int new, int flags);
 */

#ifdef __NR_dup3
static __attribute__((unused))
int sys_dup3(int old, int new, int flags)
{
	return my_syscall3(__NR_dup3, old, new, flags);
}

static __attribute__((unused))
int dup3(int old, int new, int flags)
{
	int ret = sys_dup3(old, new, flags);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_dup3 isn't defined, cannot implement sys_dup3()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_dup3 */


/*
 * int execve(const char *filename, char *const argv[], char *const envp[]);
 */

#ifedf __NR_execve
static __attribute__((unused))
int sys_execve(const char *filename, char *const argv[], char *const envp[])
{
	return my_syscall3(__NR_execve, filename, argv, envp);
}

static __attribute__((unused))
int execve(const char *filename, char *const argv[], char *const envp[])
{
	int ret = sys_execve(filename, argv, envp);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_execve isn't defined, cannot implement sys_execve()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_execve */

/*
 * int execveat(int dfd, const char *filename,
   char *const argv[], char *const envp[], int flags);
 */

#ifdef __NR_execveat
static __attribute__((unused))
int sys_execveat(int dfd, const char *filename,
  char *const argv[], char *const envp[], int flags)
{
	return my_syscall5(__NR_execveat, dfd, filename, argv, envp, flags);
}

static __attribute__((unused))
int execveat(int dfd, const char *filename,
  char *const argv[], char *const envp[], int flags)
{
	int ret = sys_execveat(dfd, filename, argv, envp, flags);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_execveat isn't defined, cannot implement sys_execveat()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_execveat */

/*
 * void exit(int status);
 */

static __attribute__((noreturn,unused))
void sys_exit(int status)
{
	my_syscall1(__NR_exit, status & 255);
	while(1); // shut the "noreturn" warnings.
}

static __attribute__((noreturn,unused))
void exit(int status)
{
	sys_exit(status);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_exit isn't defined, cannot implement sys_exit()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_exit */

/*
 * void exit_group(int status);
 */

static __attribute__((noreturn,unused))
void sys_exit_group(int status)
{
	my_syscall1(__NR_exit_group, status & 255);
	while(1); // shut the "noreturn" warnings.
}

static __attribute__((noreturn,unused))
void exit_group(int status)
{
	sys_exit_group(status);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_exit_group isn't defined, cannot implement sys_exit_group()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_exit_group */

/*
 * pid_t fork(void);
 */

#ifdef __NR_fork
static __attribute__((unused))
pid_t sys_fork(void)
{
	return my_syscall0(__NR_fork);
}

static __attribute__((unused))
pid_t fork(void)
{
	pid_t ret = sys_fork();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_fork isn't defined, cannot implement sys_fork()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_fork */

/*
 * long clone(unsigned long flags, void *child_stack,
     int *ptid, int *ctid,
     unsigned long newtls);
 */

#ifdef __NR_clone
static __attribute__((unused))
long sys_clone(unsigned long flags, void *child_stack,
  int *ptid, int *ctid,
  unsigned long newtls)
{ /* x86-64 */
	return my_syscall5(__NR_clone, flags, child_stack, ptid, ctid, newtls);
}

static __attribute__((unused))
long clone(unsigned long flags, void *child_stack,
  int *ptid, int *ctid,
  unsigned long newtls)
{
	pid_t ret = sys_clone(flags, child_stack, ptid, ctid, newtls);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_clone isn't defined, cannot implement sys_clone()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_clone */

/* __NR_clone3 */

/*
 * int fsync(int fd);
 */

#ifdef __NR_fsync
static __attribute__((unused))
int sys_fsync(int fd)
{
	return my_syscall1(__NR_fsync, fd);
}

static __attribute__((unused))
int fsync(int fd)
{
	int ret = sys_fsync(fd);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_fsync isn't defined, cannot implement sys_fsync()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_fsync */

/*
 * int getdents64(int fd, struct linux_dirent64 *dirp, int count);
 */

#ifdef __NR_getdents64
static __attribute__((unused))
int sys_getdents64(int fd, struct linux_dirent64 *dirp, int count)
{
	return my_syscall3(__NR_getdents64, fd, dirp, count);
}

static __attribute__((unused))
int getdents64(int fd, struct linux_dirent64 *dirp, int count)
{
	int ret = sys_getdents64(fd, dirp, count);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getdents64 isn't defined, cannot implement sys_getdents64()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getdents64 */


/*
 * pid_t getpgid(pid_t pid);
 */

#ifdef __NR_getpgid
static __attribute__((unused))
pid_t sys_getpgid(pid_t pid)
{
	return my_syscall1(__NR_getpgid, pid);
}

static __attribute__((unused))
pid_t getpgid(pid_t pid)
{
	pid_t ret = sys_getpgid(pid);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getpgid isn't defined, cannot implement sys_getpgid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getpgid */

/*
 * pid_t getpgrp(void);
 */

#ifdef __NR_getpgrp
static __attribute__((unused))
pid_t sys_getpgrp(void)
{
	return sys_getpgid(0);
}

static __attribute__((unused))
pid_t getpgrp(void)
{
	return sys_getpgrp();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getpgrp isn't defined, cannot implement sys_getpgrp()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getpgrp */

/*
 * pid_t getpid(void);
 */

#ifdef __NR_getpid
static __attribute__((unused))
pid_t sys_getpid(void)
{
	return my_syscall0(__NR_getpid);
}

static __attribute__((unused))
pid_t getpid(void)
{
	return sys_getpid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getpid isn't defined, cannot implement sys_getpid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getpid */

/*
 * pid_t getppid(void);
 */

#ifdef __NR_getppid
static __attribute__((unused))
pid_t sys_getppid(void)
{
	return my_syscall0(__NR_getppid);
}

static __attribute__((unused))
pid_t getppid(void)
{
	return sys_getppid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getppid isn't defined, cannot implement sys_getppid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getppid */

/*
 * pid_t gettid(void);
 */

#ifdef __NR_gettid
static __attribute__((unused))
pid_t sys_gettid(void)
{
	return my_syscall0(__NR_gettid);
}

static __attribute__((unused))
pid_t gettid(void)
{
	return sys_gettid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_gettid isn't defined, cannot implement sys_gettid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_gettid */

/*
 * pid_t getuid(void);
 */

#ifdef __NR_getuid
static __attribute__((unused))
pid_t sys_getuid(void)
{
	return my_syscall0(__NR_getuid);
}

static __attribute__((unused))
pid_t getuid(void)
{
	return sys_getuid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getuid isn't defined, cannot implement sys_getuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getuid */

/*
 * pid_t getgid(void);
 */

#ifdef __NR_getgid
static __attribute__((unused))
pid_t sys_getgid(void)
{
	return my_syscall0(__NR_getgid);
}

static __attribute__((unused))
pid_t getgid(void)
{
	return sys_getgid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getgid isn't defined, cannot implement sys_getgid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getgid */

/*
 * pid_t geteuid(void);
 */

#ifdef __NR_geteuid
static __attribute__((unused))
pid_t sys_geteuid(void)
{
	return my_syscall0(__NR_geteuid);
}

static __attribute__((unused))
pid_t geteuid(void)
{
	return sys_geteuid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_geteuid isn't defined, cannot implement sys_geteuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_geteuid */

/*
 * pid_t getegid(void);
 */

#ifdef __NR_geteuid
static __attribute__((unused))
pid_t sys_getegid(void)
{
	return my_syscall0(__NR_geteuid);
}

static __attribute__((unused))
pid_t getegid(void)
{
	return sys_getegid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getegid isn't defined, cannot implement sys_getegid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getegid */

/*
 * int gettimeofday(struct timeval *tv, struct timezone *tz);
 */

#ifdef __NR_gettimeofday
static __attribute__((unused))
int sys_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	return my_syscall2(__NR_gettimeofday, tv, tz);
}

static __attribute__((unused))
int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	int ret = sys_gettimeofday(tv, tz);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_gettimeofday isn't defined, cannot implement sys_gettimeofday()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_gettimeofday */

/*
 * int settimeofday(const struct timeval *tv, const struct timezone *tz);
 */

#ifdef __NR_settimeofday
static __attribute__((unused))
int sys_settimeofday(const struct timeval *tv, const struct timezone *tz)
{
	return my_syscall2(__NR_settimeofday, tv, tz);
}

static __attribute__((unused))
int settimeofday(const struct timeval *tv, const struct timezone *tz)
{
	int ret = sys_settimeofday(tv, tz);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_settimeofday isn't defined, cannot implement sys_settimeofday()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_settimeofday */

/*
 * int ioctl(int fd, unsigned long req, void *value);
 */

#ifdef __NR_ioctl
static __attribute__((unused))
int sys_ioctl(int fd, unsigned long req, void *value)
{
	return my_syscall3(__NR_ioctl, fd, req, value);
}

static __attribute__((unused))
int ioctl(int fd, unsigned long req, void *value)
{
	int ret = sys_ioctl(fd, req, value);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_ioctl isn't defined, cannot implement sys_ioctl()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_ioctl */

/*
 * int kill(pid_t pid, int signal);
 */

static __attribute__((unused))
int sys_kill(pid_t pid, int signal)
{
	return my_syscall2(__NR_kill, pid, signal);
}

static __attribute__((unused))
int kill(pid_t pid, int signal)
{
	int ret = sys_kill(pid, signal);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int link(const char *old, const char *new);
 */

static __attribute__((unused))
int sys_link(const char *old, const char *new)
{
#ifdef __NR_linkat
	return my_syscall5(__NR_linkat, AT_FDCWD, old, AT_FDCWD, new, 0);
#elif defined(__NR_link)
	return my_syscall2(__NR_link, old, new);
#else
#error Neither __NR_linkat nor __NR_link defined, cannot implement sys_link()
#endif
}

static __attribute__((unused))
int link(const char *old, const char *new)
{
	int ret = sys_link(old, new);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * off_t lseek(int fd, off_t offset, int whence);
 */

static __attribute__((unused))
off_t sys_lseek(int fd, off_t offset, int whence)
{
	return my_syscall3(__NR_lseek, fd, offset, whence);
}

static __attribute__((unused))
off_t lseek(int fd, off_t offset, int whence)
{
	off_t ret = sys_lseek(fd, offset, whence);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int mkdir(const char *path, mode_t mode);
 */

static __attribute__((unused))
int sys_mkdir(const char *path, mode_t mode)
{
#ifdef __NR_mkdirat
	return my_syscall3(__NR_mkdirat, AT_FDCWD, path, mode);
#elif defined(__NR_mkdir)
	return my_syscall2(__NR_mkdir, path, mode);
#else
#error Neither __NR_mkdirat nor __NR_mkdir defined, cannot implement sys_mkdir()
#endif
}

static __attribute__((unused))
int mkdir(const char *path, mode_t mode)
{
	int ret = sys_mkdir(path, mode);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int mknod(const char *path, mode_t mode, dev_t dev);
 */

static __attribute__((unused))
long sys_mknod(const char *path, mode_t mode, dev_t dev)
{
#ifdef __NR_mknodat
	return my_syscall4(__NR_mknodat, AT_FDCWD, path, mode, dev);
#elif defined(__NR_mknod)
	return my_syscall3(__NR_mknod, path, mode, dev);
#else
#error Neither __NR_mknodat nor __NR_mknod defined, cannot implement sys_mknod()
#endif
}

static __attribute__((unused))
int mknod(const char *path, mode_t mode, dev_t dev)
{
	int ret = sys_mknod(path, mode, dev);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

#ifndef MAP_SHARED
#define MAP_SHARED		0x01	/* Share changes */
#define MAP_PRIVATE		0x02	/* Changes are private */
#define MAP_SHARED_VALIDATE	0x03	/* share + validate extension flags */
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

static __attribute__((unused))
void *sys_mmap(void *addr, size_t length, int prot, int flags, int fd,
	       off_t offset)
{
#ifndef my_syscall6
	/* Function not implemented. */
	return (void *)-ENOSYS;
#else

	int n;

#if defined(__NR_mmap2)
	n = __NR_mmap2;
	offset >>= 12;
#else
	n = __NR_mmap;
#endif

	return (void *)my_syscall6(n, addr, length, prot, flags, fd, offset);
#endif
}

static __attribute__((unused))
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *ret = sys_mmap(addr, length, prot, flags, fd, offset);

	if ((unsigned long)ret >= -4095UL) {
		SET_ERRNO(-(long)ret);
		ret = MAP_FAILED;
	}
	return ret;
}

static __attribute__((unused))
int sys_munmap(void *addr, size_t length)
{
	return my_syscall2(__NR_munmap, addr, length);
}

static __attribute__((unused))
int munmap(void *addr, size_t length)
{
	int ret = sys_munmap(addr, length);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 * int mount(const char *source, const char *target,
 *           const char *fstype, unsigned long flags,
 *           const void *data);
 */
static __attribute__((unused))
int sys_mount(const char *src, const char *tgt, const char *fst,
                     unsigned long flags, const void *data)
{
	return my_syscall5(__NR_mount, src, tgt, fst, flags, data);
}

static __attribute__((unused))
int mount(const char *src, const char *tgt,
          const char *fst, unsigned long flags,
          const void *data)
{
	int ret = sys_mount(src, tgt, fst, flags, data);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int open(const char *path, int flags[, mode_t mode]);
 */

static __attribute__((unused))
int sys_open(const char *path, int flags, mode_t mode)
{
#ifdef __NR_openat
	return my_syscall4(__NR_openat, AT_FDCWD, path, flags, mode);
#elif defined(__NR_open)
	return my_syscall3(__NR_open, path, flags, mode);
#else
#error Neither __NR_openat nor __NR_open defined, cannot implement sys_open()
#endif
}

static __attribute__((unused))
int open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	int ret;

	if (flags & O_CREAT) {
		va_list args;

		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	ret = sys_open(path, flags, mode);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int pivot_root(const char *new, const char *old);
 */

static __attribute__((unused))
int sys_pivot_root(const char *new, const char *old)
{
	return my_syscall2(__NR_pivot_root, new, old);
}

static __attribute__((unused))
int pivot_root(const char *new, const char *old)
{
	int ret = sys_pivot_root(new, old);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int poll(struct pollfd *fds, int nfds, int timeout);
 */

static __attribute__((unused))
int sys_poll(struct pollfd *fds, int nfds, int timeout)
{
#if defined(__NR_ppoll)
	struct timespec t;

	if (timeout >= 0) {
		t.tv_sec  = timeout / 1000;
		t.tv_nsec = (timeout % 1000) * 1000000;
	}
	return my_syscall4(__NR_ppoll, fds, nfds, (timeout >= 0) ? &t : NULL, NULL);
#elif defined(__NR_poll)
	return my_syscall3(__NR_poll, fds, nfds, timeout);
#else
#error Neither __NR_ppoll nor __NR_poll defined, cannot implement sys_poll()
#endif
}

static __attribute__((unused))
int poll(struct pollfd *fds, int nfds, int timeout)
{
	int ret = sys_poll(fds, nfds, timeout);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int rename(char const *old, char const *new);
 */

static __attribute__((unused))
int sys_rename(const char *old, const char *new)
{
	return my_syscall2(__NR_rename, old, new);
}

static __attribute__((unused))
int rename(const char *old, const char *new)
{
	ssize_t ret = sys_rename(old, new);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 * ssize_t read(int fd, void *buf, size_t count);
 */

static __attribute__((unused))
ssize_t sys_read(int fd, void *buf, size_t count)
{
	return my_syscall3(__NR_read, fd, buf, count);
}

static __attribute__((unused))
ssize_t read(int fd, void *buf, size_t count)
{
	ssize_t ret = sys_read(fd, buf, count);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int reboot(int cmd);
 * <cmd> is among LINUX_REBOOT_CMD_*
 */

static __attribute__((unused))
ssize_t sys_reboot(int magic1, int magic2, int cmd, void *arg)
{
	return my_syscall4(__NR_reboot, magic1, magic2, cmd, arg);
}

static __attribute__((unused))
int reboot(int cmd)
{
	int ret = sys_reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, 0);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int sched_yield(void);
 */

static __attribute__((unused))
int sys_sched_yield(void)
{
	return my_syscall0(__NR_sched_yield);
}

static __attribute__((unused))
int sched_yield(void)
{
	int ret = sys_sched_yield();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int select(int nfds, fd_set *read_fds, fd_set *write_fds,
 *            fd_set *except_fds, struct timeval *timeout);
 */

static __attribute__((unused))
int sys_select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *timeout)
{
#if defined(__ARCH_WANT_SYS_OLD_SELECT) && !defined(__NR__newselect)
	struct sel_arg_struct {
		unsigned long n;
		fd_set *r, *w, *e;
		struct timeval *t;
	} arg = { .n = nfds, .r = rfds, .w = wfds, .e = efds, .t = timeout };
	return my_syscall1(__NR_select, &arg);
#elif defined(__ARCH_WANT_SYS_PSELECT6) && defined(__NR_pselect6)
	struct timespec t;

	if (timeout) {
		t.tv_sec  = timeout->tv_sec;
		t.tv_nsec = timeout->tv_usec * 1000;
	}
	return my_syscall6(__NR_pselect6, nfds, rfds, wfds, efds, timeout ? &t : NULL, NULL);
#elif defined(__NR__newselect) || defined(__NR_select)
#ifndef __NR__newselect
#define __NR__newselect __NR_select
#endif
	return my_syscall5(__NR__newselect, nfds, rfds, wfds, efds, timeout);
#else
#error None of __NR_select, __NR_pselect6, nor __NR__newselect defined, cannot implement sys_select()
#endif
}

static __attribute__((unused))
int select(int nfds, fd_set *rfds, fd_set *wfds, fd_set *efds, struct timeval *timeout)
{
	int ret = sys_select(nfds, rfds, wfds, efds, timeout);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int setpgid(pid_t pid, pid_t pgid);
 */

static __attribute__((unused))
int sys_setpgid(pid_t pid, pid_t pgid)
{
	return my_syscall2(__NR_setpgid, pid, pgid);
}

static __attribute__((unused))
int setpgid(pid_t pid, pid_t pgid)
{
	int ret = sys_setpgid(pid, pgid);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * pid_t setsid(void);
 */

static __attribute__((unused))
pid_t sys_setsid(void)
{
	return my_syscall0(__NR_setsid);
}

static __attribute__((unused))
pid_t setsid(void)
{
	pid_t ret = sys_setsid();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int stat(const char *path, struct stat *buf);
 * Warning: the struct stat's layout is arch-dependent.
 */

static __attribute__((unused))
int sys_stat(const char *path, struct stat *buf)
{
	struct sys_stat_struct stat;
	long ret;

#ifdef __NR_newfstatat
	/* only solution for arm64 */
	ret = my_syscall4(__NR_newfstatat, AT_FDCWD, path, &stat, 0);
#elif defined(__NR_stat)
	ret = my_syscall2(__NR_stat, path, &stat);
#else
#error Neither __NR_newfstatat nor __NR_stat defined, cannot implement sys_stat()
#endif
	buf->st_dev     = stat.st_dev;
	buf->st_ino     = stat.st_ino;
	buf->st_mode    = stat.st_mode;
	buf->st_nlink   = stat.st_nlink;
	buf->st_uid     = stat.st_uid;
	buf->st_gid     = stat.st_gid;
	buf->st_rdev    = stat.st_rdev;
	buf->st_size    = stat.st_size;
	buf->st_blksize = stat.st_blksize;
	buf->st_blocks  = stat.st_blocks;
	buf->st_atime   = stat.st_atime;
	buf->st_mtime   = stat.st_mtime;
	buf->st_ctime   = stat.st_ctime;
	return ret;
}

static __attribute__((unused))
int stat(const char *path, struct stat *buf)
{
	int ret = sys_stat(path, buf);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int symlink(const char *old, const char *new);
 */

static __attribute__((unused))
int sys_symlink(const char *old, const char *new)
{
#ifdef __NR_symlinkat
	return my_syscall3(__NR_symlinkat, old, AT_FDCWD, new);
#elif defined(__NR_symlink)
	return my_syscall2(__NR_symlink, old, new);
#else
#error Neither __NR_symlinkat nor __NR_symlink defined, cannot implement sys_symlink()
#endif
}

static __attribute__((unused))
int symlink(const char *old, const char *new)
{
	int ret = sys_symlink(old, new);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * mode_t umask(mode_t mode);
 */

static __attribute__((unused))
mode_t sys_umask(mode_t mode)
{
	return my_syscall1(__NR_umask, mode);
}

static __attribute__((unused))
mode_t umask(mode_t mode)
{
	return sys_umask(mode);
}


/*
 * int umount2(const char *path, int flags);
 */

static __attribute__((unused))
int sys_umount2(const char *path, int flags)
{
	return my_syscall2(__NR_umount2, path, flags);
}

static __attribute__((unused))
int umount2(const char *path, int flags)
{
	int ret = sys_umount2(path, flags);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int unlink(const char *path);
 */

static __attribute__((unused))
int sys_unlink(const char *path)
{
#ifdef __NR_unlinkat
	return my_syscall3(__NR_unlinkat, AT_FDCWD, path, 0);
#elif defined(__NR_unlink)
	return my_syscall1(__NR_unlink, path);
#else
#error Neither __NR_unlinkat nor __NR_unlink defined, cannot implement sys_unlink()
#endif
}

static __attribute__((unused))
int unlink(const char *path)
{
	int ret = sys_unlink(path);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * pid_t wait(int *status);
 * pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
 * pid_t waitpid(pid_t pid, int *status, int options);
 */

static __attribute__((unused))
pid_t sys_wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
	return my_syscall4(__NR_wait4, pid, status, options, rusage);
}

static __attribute__((unused))
pid_t wait(int *status)
{
	pid_t ret = sys_wait4(-1, status, 0, NULL);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

static __attribute__((unused))
pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage)
{
	pid_t ret = sys_wait4(pid, status, options, rusage);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


static __attribute__((unused))
pid_t waitpid(pid_t pid, int *status, int options)
{
	pid_t ret = sys_wait4(pid, status, options, NULL);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * ssize_t write(int fd, const void *buf, size_t count);
 */

static __attribute__((unused))
ssize_t sys_write(int fd, const void *buf, size_t count)
{
	return my_syscall3(__NR_write, fd, buf, count);
}

static __attribute__((unused))
ssize_t write(int fd, const void *buf, size_t count)
{
	ssize_t ret = sys_write(fd, buf, count);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


#endif /* _NOLIBC_SYS_H */
