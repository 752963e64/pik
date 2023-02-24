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
 * #include <sys/socket.h>

 *      int accept(int sockfd, struct sockaddr *restrict addr,
 *        socklen_t *restrict addrlen);

 *     #define _GNU_SOURCE
 *      #include <sys/socket.h>

 *      int accept4(int sockfd, struct sockaddr *restrict addr,
 *        socklen_t *restrict addrlen, int flags);
 */

#ifdef __NR_accept
static __attribute__((unused))
int sys_accept(int sockfd,
  struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return my_syscall3(__NR_accept, sockfd, addr, addrlen);
}

static __attribute__((unused))
int accept(int sockfd,
  struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	int ret = sys_accept(sockfd, addr, addrlen);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_accept isn't defined, cannot implement sys_accept()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_accept */

/* __GNU_SOURCE */

#ifdef __NR_accept4
static __attribute__((unused))
int sys_accept4(int sockfd,
  struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags)
{
	return my_syscall3(__NR_accept4, sockfd, addr, addrlen, flags);
}

static __attribute__((unused))
int accept4(int sockfd,
  struct sockaddr *restrict addr, socklen_t *restrict addrlen, int flags)
{
	int ret = sys_accept4(sockfd, addr, addrlen, flags);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_accept4 isn't defined, cannot implement sys_accept4()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_accept4 */

/*
 * #include <unistd.h>
 *
 * int access(const char *pathname, int mode);
 *
 * #include <fcntl.h>
 * #include <unistd.h>
 *
 * int faccessat(int dirfd, const char *pathname, int mode, int flags);
 *
 * #include <fcntl.h>
 * #include <sys/syscall.h>
 * #include <unistd.h>
 *
 * int syscall(SYS_faccessat2,
 *   int dirfd, const char *pathname, int mode, int flags);
 */

#ifdef __NR_access
static __attribute__((unused))
int sys_access(const char *pathname, int mode)
{
	return my_syscall2(__NR_access, pathname, mode);
}

static __attribute__((unused))
int access(const char *pathname, int mode)
{
	int ret = sys_access(pathname, mode);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_access isn't defined, cannot implement sys_access()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_access */


/*
 * #include <keyutils.h>
 *
 * key_serial_t add_key(const char *type, const char *description,
 *                           const void *payload, size_t plen,
 *                           key_serial_t keyring);
 *
 */

#ifdef __NR_add_key
static __attribute__((unused))
int sys_add_key(const char *type,
  const char *description, const void *payload, size_t plen, key_serial_t keyring)
{
	return my_syscall5(__NR_add_key, type, description, payload, plen, keyring);
}

static __attribute__((unused))
int add_key(const char *type,
  const char *description, const void *payload, size_t plen, key_serial_t keyring)
{
	int ret = sys_add_key(type, description, payload, plen, keyring);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_add_key isn't defined, cannot implement sys_add_key()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_add_key */

/*
 *      #include <sys/timex.h>
 *      int adjtimex(struct timex *buf);
 *      int clock_adjtime(clockid_t clk_id, struct timex *buf);
 *      int ntp_adjtime(struct timex *buf);
*/

#ifdef __NR_adjtime
static __attribute__((unused))
int sys_adjtime(struct timex *buf)
{
	return my_syscall1(__NR_adjtime, buf);
}

static __attribute__((unused))
int adjtime(struct timex *buf)
{
	int ret = sys_adjtime(buf);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_adjtime isn't defined, cannot implement sys_adjtime()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_adjtime */

/* __NR_afs_syscall */

/*
  #include <unistd.h>
  unsigned int alarm(unsigned int seconds);
*/

#ifdef __NR_alarm
static __attribute__((unused))
int sys_alarm(unsigned int seconds)
{
	return my_syscall1(__NR_alarm, seconds);
}

static __attribute__((unused))
int alarm(unsigned int seconds)
{
	int ret = sys_alarm(seconds);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_alarm isn't defined, cannot implement sys_alarm()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_alarm */


/*
 *       #include <asm/prctl.h>
 *      #include <sys/syscall.h>
 *      #include <unistd.h>
 *      int syscall(SYS_arch_prctl, int code, unsigned long addr);
 *      int syscall(SYS_arch_prctl, int code, unsigned long *addr);
 */

#ifdef __NR_arch_prctl
static __attribute__((unused))
int sys_arch_prctl(int code, unsigned long addr)
{
	return my_syscall2(__NR_arch_prctl, code, addr);
}

static __attribute__((unused))
int arch_prctl(int code, unsigned long addr)
{
	int ret = sys_arch_prctl(code, addr);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_arch_prctl isn't defined, cannot implement sys_arch_prctl()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_arch_prctl */

/*
 *  #include <sys/socket.h>
 *  int bind(int sockfd, const struct sockaddr *addr,
 *    socklen_t addrlen);
 */

#ifdef __NR_bind
static __attribute__((unused))
int sys_bind(int sockfd,
  const struct sockaddr *addr, socklen_t addrlen)
{
	return my_syscall3(__NR_bind, sockfd, addr, addrlen);
}

static __attribute__((unused))
int bind(int sockfd,
  const struct sockaddr *addr, socklen_t addrlen)
{
	int ret = sys_bind(sockfd, addr, addrlen);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_bind isn't defined, cannot implement sys_bind()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_bind */

/*
 *  #include <linux/bpf.h>
 *  int bpf(int cmd, union bpf_attr *attr, unsigned int size);
*/

#ifdef __NR_bpf
static __attribute__((unused))
int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return my_syscall3(__NR_bpf, cmd, attr, size);
}

static __attribute__((unused))
int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	int ret = sys_bpf(cmd, attr, size);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_bpf isn't defined, cannot implement sys_bpf()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_bpf */

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
* #include <linux/capability.h>
  #include <sys/syscall.h>
  #include <unistd.h>
*  int syscall(SYS_capget, cap_user_header_t hdrp,
*    cap_user_data_t datap);
*  int syscall(SYS_capset, cap_user_header_t hdrp,
*                   const cap_user_data_t datap);
*/

#ifdef __NR_capget
static __attribute__((unused))
int sys_capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
	return my_syscall1(__NR_capget, hdrp, datap);
}

static __attribute__((unused))
int capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
	int ret = sys_capget(hdrp, datap);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_capget isn't defined, cannot implement sys_capget()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_capget */

#ifdef __NR_capset
static __attribute__((unused))
int sys_chdir(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return my_syscall1(__NR_capset, hdrp, datap);
}

static __attribute__((unused))
int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	int ret = sys_capset(hdrp, datap);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_capset isn't defined, cannot implement sys_capset()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_capset */


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
 * int clock_adjtime(clockid_t clk_id, struct timex *buf);
 */

#ifdef __NR_clock_adjtime
static __attribute__((unused))
int sys_clock_adjtime(clockid_t clk_id, struct timex *buf)
{
	return my_syscall2(__NR_clock_adjtime, clk_id, buf);
}

static __attribute__((unused))
int clock_adjtime(clockid_t clk_id, struct timex *buf)
{
	int ret = sys_clock_adjtime(clk_id, buf);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_clock_adjtime isn't defined, cannot implement sys_clock_adjtime()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_clock_adjtime */

/*
 * #include <time.h>
 * int clock_getres(clockid_t clockid, struct timespec *res);
 */

#ifdef __NR_clock_getres
static __attribute__((unused))
int sys_clock_getres(clockid_t clk_id, struct timespec *res)
{
	return my_syscall2(__NR_clock_getres, clk_id, res);
}

static __attribute__((unused))
int clock_getres(clockid_t clk_id, struct timespec *res)
{
	int ret = sys_clock_getres(clk_id, res);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_clock_getres isn't defined, cannot implement sys_clock_getres()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_clock_getres */

/*
 * #include <time.h>
 * int clock_gettime(clockid_t clockid, struct timespec *tp);
 */

#ifdef __NR_clock_gettime
static __attribute__((unused))
int sys_clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	return my_syscall2(__NR_clock_gettime, clk_id, tp);
}

static __attribute__((unused))
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	int ret = sys_clock_gettime(clk_id, tp);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_clock_gettime isn't defined, cannot implement sys_clock_gettime()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_clock_gettime */

/*
 * int clock_nanosleep(clockid_t clockid, int flags,
 *                          const struct timespec *request,
 *                          struct timespec *remain);
 */

#ifdef __NR_clock_nanosleep
static __attribute__((unused))
int sys_clock_nanosleep(clockid_t clk_id,
  int flags, const struct timespec *request, struct timespec *remain)
{
	return my_syscall4(__NR_clock_nanosleep, clk_id, flags, request, remain);
}

static __attribute__((unused))
int clock_nanosleep(clockid_t clk_id,
  int flags, const struct timespec *request, struct timespec *remain)
{
	int ret = sys_clock_nanosleep(clk_id, flags, request, remain);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_clock_nanosleep isn't defined, cannot implement sys_clock_nanosleep()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_clock_nanosleep */

/*
 * #include <time.h>
 * int clock_settime(clockid_t clockid, const struct timespec *tp);
 */

#ifdef __NR_clock_settime
static __attribute__((unused))
int sys_clock_settime(clockid_t clk_id, const struct timespec *tp)
{
	return my_syscall2(__NR_clock_settime, clk_id, tp);
}

static __attribute__((unused))
int clock_settime(clockid_t clk_id, const struct timespec *tp)
{
	int ret = sys_clock_settime(clk_id, tp);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_clock_settime isn't defined, cannot implement sys_clock_settime()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_clock_settime */

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
 * #include <linux/close_range.h>
 * int close_range(unsigned int first, unsigned int last,
 *                      unsigned int flags);
 */

#ifedf __NR_close_range
static __attribute__((unused))
int sys_close_range(unsigned int first, unsigned int last, unsigned int flags)
{
	return my_syscall3(__NR_close_range, first, last, flags);
}

static __attribute__((unused))
int close_range(unsigned int first, unsigned int last, unsigned int flags)
{
	int ret = sys_close(first, last, flags);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_close_range isn't defined, cannot implement sys_close_range()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_close_range */

/*
 * #include <sys/socket.h>
 * int connect(int sockfd, const struct sockaddr *addr,
 *                  socklen_t addrlen);
 */

#ifedf __NR_connect
static __attribute__((unused))
int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return my_syscall3(__NR_cconnect, sockfd, addr, addrlen);
}

static __attribute__((unused))
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	int ret = sys_connect(sockfd, addr, addrlen);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_connect isn't defined, cannot implement sys_connect()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_connect */

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
 * int getcpu(unsigned int *cpu, unsigned int *node);
 */

#ifdef __NR_getcpu
static __attribute__((unused))
int sys_getcpu(unsigned int *cpu, unsigned int *node)
{
	return my_syscall2(__NR_getcpu, cpu, node);
}

static __attribute__((unused))
int getcpu(unsigned int *cpu, unsigned int *node)
{
	int ret = sys_getcpu(cpu, node);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getcpu isn't defined, cannot implement sys_getcpu()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getcpu */

/*
 char *getcwd(char *buf, size_t size);
*/

#ifdef __NR_gecwd
static __attribute__((unused))
int sys_getcwd(char *buf, size_t size)
{
	return my_syscall2(__NR_getcwd, buf, size);
}

static __attribute__((unused))
int getcwd(char *buf, size_t size)
{
	int ret = sys_getcwd(buf, size);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getcwd isn't defined, cannot implement sys_getcwd()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getcwd */

/*
 * int getdents(unsigned int fd,
 *  struct linux_dirent *dirp, unsigned int count)
 */

#ifdef __NR_getdents
static __attribute__((unused))
int sys_getdents(unsigned int fd,
  struct linux_dirent *dirp, unsigned int count)
{
	return my_syscall3(__NR_getdents, fd, dirp, count);
}

static __attribute__((unused))
int getdents(unsigned int fd,
  struct linux_dirent *dirp, unsigned int count)
{
	int ret = sys_getdents(fd, dirp, count);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getdents isn't defined, cannot implement sys_getdents()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getdents */

/*
 * int getdents64(unsigned int fd,
 *  struct linux_dirent64 *dirp, unsigned int count)
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
 * int getdomainname(char *name, size_t len);
 */

#ifdef __NR_getdomainename
static __attribute__((unused))
int sys_getdomainename(char *name, size_t len)
{
	return my_syscall2(__NR_getdomainename, name, len);
}

static __attribute__((unused))
int getdomainename(char *name, size_t len)
{
	int ret = sys_getdomainename(name, len);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getdomainename isn't defined, cannot implement sys_getdomainename()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getdomainename */

/*
 * gid_t getegid(void);
 */

#ifdef __NR_getegid
static __attribute__((unused))
gid_t sys_getegid(void)
{
	return my_syscall0(__NR_getegid);
}

static __attribute__((unused))
gid_t getegid(void)
{
	return sys_getegid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getegid isn't defined, cannot implement sys_getegid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getegid */

/*
 * uid_t geteuid(void);
 */

#ifdef __NR_geteuid
static __attribute__((unused))
uid_t sys_geteuid(void)
{
	return my_syscall0(__NR_geteuid);
}

static __attribute__((unused))
uid_t geteuid(void)
{
	return sys_geteuid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_geteuid isn't defined, cannot implement sys_geteuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_geteuid */

/*
 * gid_t getgid(void);
 */

#ifdef __NR_getgid
static __attribute__((unused))
gid_t sys_getgid(void)
{
	return my_syscall0(__NR_getgid);
}

static __attribute__((unused))
gid_t getgid(void)
{
	return sys_getgid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getgid isn't defined, cannot implement sys_getgid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getgid */

/*
 * int getgroups(int size, gid_t list[]);
 */

#ifdef __NR_getgroups
static __attribute__((unused))
pid_t sys_getgroups(int size, gid_t list[])
{
	return my_syscall2(__NR_getgroups, size, list);
}

static __attribute__((unused))
pid_t getgroups(int size, gid_t list[])
{
	pid_t ret = sys_getgroups(size, list);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getgroups isn't defined, cannot implement sys_getgroups()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getgroups */


/*
 * int gethostname(char *name, size_t len);
 */

#ifdef __NR_gethostname
static __attribute__((unused))
int sys_gethostname(char *name, size_t len)
{
	return my_syscall1(__NR_gethostname, name, len);
}

static __attribute__((unused))
int gethostname(char *name, size_t len)
{
	int ret = sys_gethostname(char *name, size_t len);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_gethostanme isn't defined, cannot implement sys_gethostname()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_gethostname */

/*
 *  int getitimer(int which, struct itimerval *curr_value);
 */

#ifdef __NR_getitimer
static __attribute__((unused))
int sys_getitimer(int which, struct itimerval *curr_value)
{
	return my_syscall2(__NR_getitimer, which, curr_value);
}

static __attribute__((unused))
int getitimer(int which, struct itimerval *curr_value)
{
	int ret = sys_getitimer(which, curr_value);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getitimer isn't defined, cannot implement sys_getitimer()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getitimer */


/*
 * int getpeername(int sockfd, struct sockaddr *restrict addr,
 *                      socklen_t *restrict addrlen);
 */

#ifdef __NR_getpeername
static __attribute__((unused))
int sys_getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return my_syscall2(__NR_getpeername, sockfd, addr, addrlen);
}

static __attribute__((unused))
int getpeername(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	int ret = sys_getpeername(sockfd, addr, addrlen);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getpeername isn't defined, cannot implement sys_getpeername()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getpeername */


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
uid_t sys_getpgrp(void)
{
	return my_syscall0(__NR_getpgrp);
}
static __attribute__((unused))
pid_t sys_getpgrp(void)
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
 * int getpriority(int which, id_t who);
 */

#ifdef __NR_getpriority
static __attribute__((unused))
int sys_getpriority(int which, id_t who)
{
	return my_syscall2(__NR_getpriority, which, who);
}

static __attribute__((unused))
int getppriority(int which, id_t who)
{
	return sys_getpriority(which, who);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getpriority isn't defined, cannot implement sys_getpriority()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getpriority */

/*
 * ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
 */

#ifdef __NR_getrandom
static __attribute__((unused))
ssize_t sys_getrandom(void *buf, size_t buflen, unsigned int flags)
{
	return my_syscall3(__NR_getrandom, buf, buflen, flags);
}

static __attribute__((unused))
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
	return sys_getrandom(buf, buflen, flags);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getrandom isn't defined, cannot implement sys_getrandom()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getrandom */

/*
 * int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);
 */

#ifdef __NR_getresgid
static __attribute__((unused))
pid_t sys_getresgid(uid_t *ruid, uid_t *euid, gid_t *sgid)
{
	return my_syscall3(__NR_getresgid, ruid, euid, sgid);
}

static __attribute__((unused))
pid_t getresgid(uid_t *ruid, uid_t *euid, gid_t *sgid)
{
	return sys_getresgid(ruid, euid, sgid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getresgid isn't defined, cannot implement sys_getresgid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getresgid */

/*
 * int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);
 */

#ifdef __NR_getresuid
static __attribute__((unused))
pid_t sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
	return my_syscall3(__NR_getresuid, ruid, euid, suid);
}

static __attribute__((unused))
pid_t getresuid(uid_t *ruid, uid_t *euid, gid_t *sgid)
{
	return sys_getresuid(ruid, euid, sgid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getresuid isn't defined, cannot implement sys_getresuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getresuid */


/******************************************************/

/*
int getrlimit(int resource, struct rlimit *rlim);
*/

#ifdef __NR_getrlimit
static __attribute__((unused))
int sys_getrlimit(int resource, struct rlimit *rlim)
{
	return my_syscall2(__NR_getrlimit, resource, rlim);
}

static __attribute__((unused))
int getrlimit(int resource, struct rlimit *rlim)
{
	return sys_getrlimit(resource, rlimit, rlim);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getrlmit isn't defined, cannot implement sys_getrlimit()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getrlimit */

/*
 * int prlimit(pid_t pid, int resource, const struct rlimit *new_limit,
 *                  struct rlimit *old_limit);
 */

/*
 * int getrusage(int who, struct rusage *usage);
 */

#ifdef __NR_getrusage
static __attribute__((unused))
int sys_getrusage(int who, struct rusage *usage)
{
	return my_syscall2(__NR_getrusage, who, usage);
}

static __attribute__((unused))
int getrusage(int who, struct rusage *usage)
{
	return sys_getrusage(who, usage);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getrusage isn't defined, cannot implement sys_getrusage()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getrusage */

/*
 * pid_t getsid(pid_t pid);
 */

#ifdef __NR_getsid
static __attribute__((unused))
pid_t sys_getsid(pid_t pid)
{
	return my_syscall1(__NR_setsid, pid);
}

static __attribute__((unused))
pid_t getsid(pid_t pid)
{
	pid_t ret = sys_getsid(pid);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getsid isn't defined, cannot implement sys_getsid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getsid */

/*
 * int getsockname(int sockfd, struct sockaddr *restrict addr,
 *                      socklen_t *restrict addrlen);
 */

#ifdef __NR_getsockname()
static __attribute__((unused))
int sys_getsockname(int sockfd,
  struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	return my_syscall3(__NR_getsockname, sockfd, addr, addrlen);
}

static __attribute__((unused))
int getsockname(int sockfd,
  struct sockaddr *restrict addr, socklen_t *restrict addrlen)
{
	pid_t ret = sys_getsockname(int sockfd,
    struct sockaddr *restrict addr, socklen_t *restrict addrlen);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getsockname isn't defined, cannot implement sys_getsockname()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getsockname */

/*
 * int getsockopt(int sockfd, int level, int optname,
 *       void *restrict optval, socklen_t *restrict optlen);
 */

#ifdef __NR_getsockopt()
static __attribute__((unused))
int sys_getsockopt(int sockfd, int level, int optname,
  void *restrict optval, socklen_t *restrict optlen)
{
	return my_syscall5(__NR_getsockopt, sockfd, level, optname, optval, optlen);
}

static __attribute__((unused))
int getsockopt(int sockfd, int level, int optname,
  void *restrict optval, socklen_t *restrict optlen)
{
	int ret = sys_getsockopt(sockfd, level, optname, optval, optlen);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getsockopt isn't defined, cannot implement sys_getsockopt()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getsockopt */

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
 * uid_t getuid(void);
 */

#ifdef __NR_getuid
static __attribute__((unused))
pid_t sys_getuid(void)
{
	return my_syscall0(__NR_getuid);
}

static __attribute__((unused))
int getuid(void)
{
	return sys_getuid();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getuid isn't defined, cannot implement sys_getuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getuid */

/********************************************************************************
ssize_t getxattr(const char *path, const char *name,
                        void *value, size_t size);
*/

#ifdef __NR_getxattr
static __attribute__((unused))
ssize_t sys_getxattr(const char *path,
  const char *name, void *value, size_t size)
{
	return my_syscall4(__NR_getxattr, path, name, value, size);
}

static __attribute__((unused))
ssize_t getxattr(const char *path,
  const char *name, void *value, size_t size)
{
  int ret = sys_getxattr(path, name, value, size);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_getxattr isn't defined, cannot implement sys_getxattr()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_getxattr */


/*
 * int syscall(SYS_init_module, void *module_image, unsigned long len,
 *                  const char *param_values);
******/

static __attribute__((unused))
int sys_init_module()
{
  /* call sys_syscall */
}

static __attribute__((unused))
int init_module()
{
	return sys_init_module();
}

/*
 * int syscall(SYS_finit_module, int fd, const char *param_values,
 *                  int flags);
 *************/

static __attribute__((unused))
int sys_finit_module()
{
  /* call sys_syscall */
}

static __attribute__((unused))
int finit_module()
{
	return sys_finit_module();
}

/*
 * int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
 ***/

#ifdef __NR_inotify_add_watch
static __attribute__((unused))
int sys_inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
	return my_syscall3(__NR_inotify_add_watch, fd, pathname, mask);
}

static __attribute__((unused))
int inotify_add_watch(int fd, const char *pathname, uint32_t mask)
{
  int ret = sys_inotify_add_watch(fd, pathname, mask);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_inotify_add_watch isn't defined, cannot implement sys_inotify_add_watch()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_inotify_add_watch */

/*
  int inotify_init(void);
  int inotify_init1(int flags);
  Both available while one fits the job.
  inotify_init1(0) == inotify_init()
*/

#ifdef __NR_inotify_init
static __attribute__((unused))
int sys_inotify_init(void)
{
	return my_syscall0(__NR_inotify_init);
}

static __attribute__((unused))
int inotify_init(void)
{
  int ret = sys_inotify_init();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_inotify_init isn't defined, cannot implement sys_inotify_init()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_inotify_init */

/*****************************************************************/

#ifdef __NR_inotify_init1
static __attribute__((unused))
int sys_inotify_init1(int flags)
{
	return my_syscall1(__NR_inotify_init1, flags);
}

static __attribute__((unused))
int inotify_init1(int flags)
{
  int ret = sys_inotify_init1(flags);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_inotify_init1 isn't defined, cannot implement sys_inotify_init1()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_inotify_init1 */

/*
 * int inotify_rm_watch(int fd, int wd);
 */

#ifdef __NR_inotify_rm_watch
static __attribute__((unused))
int sys_inotify_rm_watch(int fd, int wd)
{
	return my_syscall2(__NR_inotify_rm_watch, fd, wd);
}

static __attribute__((unused))
int inotify_rm_watch(int fd, int wd)
{
  int ret = sys_inotify_rm_watch(fd, wd);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_inotify_rm_watch isn't defined, cannot implement sys_inotify_rm_watch()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_inotify_watch */

/*
 * int syscall(SYS_io_cancel,
 *   aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);
 */

#ifdef __NR_io_cancel
static __attribute__((unused))
int sys_io_cancel()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_cancel()
{
  int ret = sys_io_cancel();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_io_cancel isn't defined, cannot implement sys_io_cancel()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_io_cancel */

/*
 * int syscall(SYS_io_destroy, aio_context_t ctx_id);
 */

static __attribute__((unused))
int sys_io_cancel()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_cancel()
{
  int ret = sys_io_cancel();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/***
  * int syscall(SYS_io_getevents, aio_context_t ctx_id,
  *                 long min_nr, long nr, struct io_event *events,
  *                 struct timespec *timeout);
 */

static __attribute__((unused))
int sys_io_getevents()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_getevents()
{
  int ret = sys_io_getevents();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/***
  * int syscall(SYS_io_pgetevents, aio_context_t ctx_id,
  *                 long min_nr, long nr, struct io_event *events,
  *                 struct timespec *timeout);
 */

static __attribute__((unused))
int sys_io_pgetevents()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_pgetevents()
{
  int ret = sys_io_pgetevents();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/***
  * int syscall(SYS_io_setup, unsigned int nr_events, aio_context_t ctx_id);
 */

static __attribute__((unused))
int sys_io_setup()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_setup()
{
  int ret = sys_io_setup();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 * int syscall(SYS_io_submit, aio_context_t ctx_id, long nr, struct iocb **iocbpp);
 */

static __attribute__((unused))
int sys_io_submit()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_submit()
{
  int ret = sys_io_submit();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 *      int syscall(SYS_io_uring_enter, unsigned int fd, unsigned int to_submit,
 *                         unsigned int min_complete, unsigned int flags,
 *                         sigset_t *sig);

 *      int syscall(SYS_io_uring_enter2, unsigned int fd, unsigned int to_submit,
 *                          unsigned int min_complete, unsigned int flags,
 *                          sigset_t *sig, size_t sz);
 */

static __attribute__((unused))
int sys_io_uring_enter()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_uring_enter()
{
  int ret = sys_io_uring_enter();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int syscall(SYS_io_uring_register, unsigned int fd, unsigned int opcode,
                             void *arg, unsigned int nr_args);
 */

static __attribute__((unused))
int sys_io_uring_register()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_uring_register()
{
  int ret = sys_io_uring_register();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}


/*
 * int syscall(SYS_io_uring_setup, u32 entries, struct io_uring_params *p);
 */

static __attribute__((unused))
int sys_io_uring_setup()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int io_uring_setup()
{
  int ret = sys_io_uring_setup();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

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
 * int ioperm(unsigned long from, unsigned long num, int turn_on);
 */

#ifdef __NR_ioperm
static __attribute__((unused))
int sys_ioperm(unsigned long from, unsigned long num, int turn_on)
{
	return my_syscall3(__NR_ioperm, from, num, turn_on);
}

static __attribute__((unused))
int ioperm(unsigned long from, unsigned long num, int turn_on)
{
	int ret = sys_ioperm(from, num, turn_on);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_ioperm isn't defined, cannot implement sys_ioperm()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_ioperm */

/*
 * int iopl(int level);
 */

#ifdef __NR_iopl
static __attribute__((unused))
int sys_iopl(int level)
{
	return my_syscall1(__NR_iopl, level);
}

static __attribute__((unused))
int iopl(int level)
{
	int ret = sys_iopl(level);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_iopl isn't defined, cannot implement sys_iopl()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_iopl */

/*
 * int syscall(SYS_ioprio_get, int which, int who);
 * int syscall(SYS_ioprio_set, int which, int who, int ioprio);
 */

static __attribute__((unused))
int sys_ioprio_get()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int ioprio_get()
{
  int ret = sys_ioprio_get();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

static __attribute__((unused))
int sys_ioprio_set()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int ioprio_set()
{
  int ret = sys_ioprio_set();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
  int syscall(SYS_ipc, unsigned int call, int first,
    unsigned long second, unsigned long third, void *ptr,
    long fifth);
*/

static __attribute__((unused))
int sys_ipc()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int ipc()
{
  int ret = sys_ipc();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 int syscall(SYS_kcmp, pid_t pid1, pid_t pid2, int type,
    unsigned long idx1, unsigned long idx2);
*/

static __attribute__((unused))
int sys_kcmp()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int kcmp()
{
  int ret = sys_kcmp();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 * long syscall(SYS_kexec_load, unsigned long entry,
 *                   unsigned long nr_segments, struct kexec_segment *segments,
 *                   unsigned long flags);
 * long syscall(SYS_kexec_file_load, int kernel_fd, int initrd_fd,
 *                   unsigned long cmdline_len, const char *cmdline,
 *                   unsigned long flags);
 */

static __attribute__((unused))
int sys_kexec_load()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int kexec_load()
{
  int ret = sys_kexec_load();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

static __attribute__((unused))
int sys_kexec_file_load()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int kexec_file_load()
{
  int ret = sys_kexec_file_load();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 * long syscall(SYS_keyctl, int operation, unsigned long arg2,
 *                   unsigned long arg3, unsigned long arg4,
 *                   unsigned long arg5);
 */

static __attribute__((unused))
int sys_keyctl()
{
	/* syscall has better implementation to catch error we uses that one. */
}

static __attribute__((unused))
int keyctl()
{
  int ret = sys_keyctl();

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}

/*
 * int kill(pid_t pid, int signal);
 */
 
#ifdef __NR_kill
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
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_kill isn't defined, cannot implement sys_kill()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_kill */

/*
ssize_t lgetxattr(const char *path, const char *name,
                        void *value, size_t size);
ssize_t fgetxattr(int fd, const char *name,
                        void *value, size_t size);

*********************************************************************************/

/*
 * int setuid(uid_t uid);
 */

#ifdef __NR_setuid
static __attribute__((unused))
uid_t sys_setuid(uid_t uid)
{
	return my_syscall1(__NR_setuid, uid);
}

static __attribute__((unused))
uid_t setuid(uid_t uid)
{
	return sys_setuid(uid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setuid isn't defined, cannot implement sys_setuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setuid */

/*
 * pid_t setgid(gid_t gid);
 */

#ifdef __NR_setgid
static __attribute__((unused))
pid_t sys_setgid(gid_t gid)
{
	return my_syscall1(__NR_setgid, gid);
}

static __attribute__((unused))
pid_t setgid(gid_t gid)
{
	return sys_setgid(gid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setgid isn't defined, cannot implement sys_setgid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setgid */

/*
 * int setreuid(uid_t ruid, uid_t euid);
 */

#ifdef __NR_setreuid
static __attribute__((unused))
pid_t sys_setreuid(uid_t ruid, uid_t euid)
{
	return my_syscall2(__NR_setreuid, ruid, euid);
}

static __attribute__((unused))
pid_t setreuid(uid_t ruid, uid_t euid)
{
	return sys_setreuid(ruid, euid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setreuid isn't defined, cannot implement sys_setreuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setreuid */

/*
 *int setpgid(pid_t pid, pid_t pgid);
 */

#ifdef __NR_setpgid
static __attribute__((unused))
int sys_setpgid(pid_t pid, pid_t pgid)
{
	return my_syscall2(__NR_setpgid, pid, pgid);
}

static __attribute__((unused))
pid_t setpgid(pid_t pid, pid_t pgid)
{
	pid_t ret = sys_setpgid(pid, pgid);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setpgid isn't defined, cannot implement sys_setpgid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setpgid */

/*
 * int setregid(gid_t rgid, gid_t egid);
 */

#ifdef __NR_setregid
static __attribute__((unused))
pid_t sys_setregid(uid_t ruid, uid_t euid)
{
	return my_syscall2(__NR_setregid, ruid, euid);
}

static __attribute__((unused))
pid_t setregid(uid_t ruid, uid_t euid)
{
	return sys_setregid(ruid, euid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setregid isn't defined, cannot implement sys_setregid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setregid */


/*
 * int setregid(gid_t rgid, gid_t egid);
 */

#ifdef __NR_setregid
static __attribute__((unused))
pid_t sys_setregid(uid_t ruid, uid_t euid)
{
	return my_syscall2(__NR_setregid, ruid, euid);
}

static __attribute__((unused))
pid_t setregid(uid_t ruid, uid_t euid)
{
	return sys_setregid(ruid, euid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setregid isn't defined, cannot implement sys_setregid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setregid */










/*
 * pid_t setpgrp(void);
 * int setpgrp(void);  System V version POSIX.1
 * int setpgrp(pid_t pid, pid_t pgid); BSD version
 */

/*
 * int setresuid(uid_t ruid, uid_t euid, uid_t suid);
 */

#ifdef __NR_setresuid
static __attribute__((unused))
pid_t sys_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return my_syscall3(__NR_setresuid, ruid, euid, suid);
}

static __attribute__((unused))
pid_t setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
	return sys_setresuid(ruid, euid, suid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setresuid isn't defined, cannot implement sys_setresuid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setresuid */

#ifdef __NR_setpgrp
static __attribute__((unused))
uid_t sys_setpgrp(void)
{
	return my_syscall2(__NR_setpgid, 0, 0);
}

static __attribute__((unused))
pid_t sys_setpgrp(void)
{
	return sys_setpgrp();
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setpgrp isn't defined, cannot implement sys_setpgrp()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setpgrp */

/*
 * int setdomainname(const char *name, size_t len);
 */

#ifdef __NR_setdomainename
static __attribute__((unused))
int sys_setdomainename(const char *name, size_t len)
{
	return my_syscall2(__NR_setdomainename, name, len);
}

static __attribute__((unused))
int setdomainename(const char *name, size_t len)
{
	int ret = sys_setdomainename(name, len);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setdomainename isn't defined, cannot implement sys_setdomainename()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setdomainename */

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
int setrlimit(int resource, const struct rlimit *rlim);
*/

#ifdef __NR_setrlimit
static __attribute__((unused))
int sys_setrlimit(int resource, const struct rlimit *rlim)
{
	return my_syscall2(__NR_setrlimit, resource, rlim);
}

static __attribute__((unused))
int setrlimit(int resource, struct rlimit *rlim)
{
	return sys_setrlimit(resource, rlim);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setrlmit isn't defined, cannot implement sys_setrlimit()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setrlimit */

/*
 * int setgroups(size_t size, const gid_t *list);
 */

#ifdef __NR_setgroups
static __attribute__((unused))
pid_t sys_setgroups(size_t size, const gid_t list[])
{
	return my_syscall2(__NR_setgroups, size, list);
}

static __attribute__((unused))
pid_t setgroups(size_t size, gid_t list[])
{
	pid_t ret = sys_setgroups(size, list);

	if (ret < 0) {
		SET_ERRNO(-ret);
		ret = -1;
	}
	return ret;
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setgroups isn't defined, cannot implement sys_setgroups()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setgroups */

/*
       int sethostname(const char *name, size_t len);
       int setitimer(int which, const struct itimerval *restrict new_value,
                     struct itimerval *restrict old_value);
*/


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
 * int setpriority(int which, id_t who, int prio);
 */

#ifdef __NR_setpriority
static __attribute__((unused))
int sys_setpriority(int which, id_t who, int prio)
{
	return my_syscall3(__NR_setpriority, which, who, prio);
}

static __attribute__((unused))
int setppriority(int which, id_t who, int prio)
{
	return sys_setpriority(which, who, prio);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setpriority isn't defined, cannot implement sys_setppriority()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setpriority */

/*
 *int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
 */

#ifdef __NR_setresgid
static __attribute__((unused))
int sys_setresgid(uid_t ruid, uid_t euid, gid_t sgid)
{
	return my_syscall3(__NR_setresgid, ruid, euid, sgid);
}

static __attribute__((unused))
int setresgid(uid_t ruid, uid_t euid, gid_t sgid)
{
	return sys_setresgid(ruid, euid, sgid);
}
#else
#ifdef __NOLIBC_TEST_SYS
#error __NR_setresgid isn't defined, cannot implement sys_setresgid()
#endif /* __NOLIBC_TEST_SYS */
#endif /* __NR_setresgid */


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
