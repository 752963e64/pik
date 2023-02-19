/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * Standard definitions and types for NOLIBC
 * Copyright (C) 2017-2021 Willy Tarreau <w@1wt.eu>
 *
 * Added some standard type definitions.
 * previously std.h renamed to stdint.h. HackIT
 */

#ifndef _NOLIBC_STDINT_H
#define _NOLIBC_STDINT_H

/* Declare a few quite common macros and types that usually are in stdlib.h,
 * stdint.h, ctype.h, unistd.h and a few other common locations. Please place
 * integer type definitions and generic macros here, but avoid OS-specific and
 * syscall-specific stuff, as this file is expected to be included very early.
 */

/* note: may already be defined */
#ifndef NULL
#define NULL ((void *)0)
#endif

/* exact width integer types */
#define INT8_MIN CHAR_MIN
#define INT8_MAX CHAR_MAX
#define INT16_MIN SHRT_MIN
#define INT16_MAX SHRT_MAX
#define INT32_MIN INT_MIN
#define INT32_MAX INT_MAX
#define INT64_MIN LLONG_MIN
#define INT64_MAX LLONG_MAX
#define UINT8_MAX UCHAR_MAX
#define UINT16_MAX USHRT_MAX
#define UINT32_MAX UINT_MAX
#define UINT64_MAX ULLONG_MAX
typedef unsigned char       uint8_t;
typedef   signed char        int8_t;
typedef unsigned short     uint16_t;
typedef   signed short      int16_t;
typedef unsigned int       uint32_t;
typedef   signed int        int32_t;
typedef unsigned long long uint64_t;
typedef   signed long long  int64_t;


/* minimum width integer types */
#define INT_LEAST8_MIN CHAR_MIN
#define INT_LEAST8_MAX CHAR_MAX
#define INT_LEAST16_MIN SHRT_MIN
#define INT_LEAST16_MAX SHRT_MAX
#define INT_LEAST32_MIN INT_MIN
#define INT_LEAST32_MAX INT_MAX
#define INT_LEAST64_MIN LLONG_MIN
#define INT_LEAST64_MAX LLONG_MAX
#define UINT_LEAST8_MAX UCHAR_MAX
#define UINT_LEAST16_MAX USHRT_MAX
#define UINT_LEAST32_MAX UINT_MAX
#define UINT_LEAST64_MAX ULLONG_MAX
typedef unsigned char       uint_least8_t;
typedef   signed char        int_least8_t;
typedef unsigned short     uint_least16_t;
typedef   signed short      int_least16_t;
typedef unsigned int       uint_least32_t;
typedef   signed int        int_least32_t;
typedef unsigned long long uint_least64_t;
typedef   signed long long  int_least64_t;


/* fastest width integer types */
#define INT_FAST8_MIN CHAR_MIN
#define INT_FAST8_MAX CHAR_MAX
#define INT_FAST16_MIN SHRT_MIN
#define INT_FAST16_MAX SHRT_MAX
#define INT_FAST32_MIN INT_MIN
#define INT_FAST32_MAX INT_MAX
#define INT_FAST64_MIN LLONG_MIN
#define INT_FAST64_MAX LLONG_MAX
#define UINT_FAST8_MAX UCHAR_MAX
#define UINT_FAST16_MAX USHRT_MAX
#define UINT_FAST32_MAX UINT_MAX
#define UINT_FAST64_MAX ULLONG_MAX
typedef unsigned char       uint_fast8_t;
typedef   signed char        int_fast8_t;
typedef unsigned short     uint_fast16_t;
typedef   signed short      int_fast16_t;
typedef unsigned int       uint_fast32_t;
typedef   signed int        int_fast32_t;
typedef unsigned long long uint_fast64_t;
typedef   signed long long  int_fast64_t;


/* integer types capable of holding object pointers */
#define INTPTR_MIN LONG_MIN
#define INTPTR_MAX LONG_MAX
#define UINTPTR_MAX ULONG_MAX
typedef unsigned long     uintptr_t;
typedef   signed long      intptr_t;


/* greatest width integer types */
#define INTMAX_MIN LLONG_MIN
#define INTMAX_MAX LLONG_MAX
#define UINTMAX_MAX ULLONG_MAX
typedef signed long long     intmax_t;
typedef unsigned long long  uintmax_t;


typedef unsigned long        size_t;
typedef   signed long       ssize_t;
typedef   signed long     ptrdiff_t;

/* those are commonly provided by sys/types.h */
typedef unsigned int          dev_t;
typedef unsigned long         ino_t;
typedef unsigned int         mode_t;
typedef   signed int          pid_t;
typedef unsigned int          uid_t;
typedef unsigned int          gid_t;
typedef unsigned long       nlink_t;
typedef   signed long         off_t;
typedef   signed long     blksize_t;
typedef   signed long      blkcnt_t;
typedef   signed long        time_t;

#endif /* _NOLIBC_STDINT_H */
