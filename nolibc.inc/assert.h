/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * Standard diagnostics for NOLIBC
 * Copyright (C) 2023 HackIT 752963e64 @ tutanota.com
 */

#ifndef _NOLIBC_ASSERT_H
#define _NOLIBC_ASSERT_H

#undef assert

static void
__assert( char const *, int, char const *, char const * );

#define assert( x )    \
     ( (x)             \
     ? (void)0         \
     : __assert( __FILE__, __LINE__, __func__, #x ))

#ifdef NDEBUG
#define assert(x) ((void)0)
#endif

static void
__assert( char const * file, int line, char const * func, char const * expr )
{
     printf("%s:%d: %s: Assertion '%s' failed.\n", file, line, func, expr);
     abort();
}

#endif

