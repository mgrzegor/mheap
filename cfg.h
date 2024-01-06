/*
 * cfg.h - Basic definitions and environment configuration
 *
 * MUST be included before any system headers!
 *
 * Copyright 2011--2024 Marcin Grzegorczyk
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 * OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef CFG_H
#define CFG_H

#ifndef NO_STDC_CHECK
  #if __STDC_VERSION__ < 199901L
    #error C99 or later required
  #endif
#endif

#include <stddef.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>


#if __STDC_VERSION__ >= 201112L
  #define NORETURN _Noreturn
#endif


#ifndef NO_EXTENSIONS
  #ifdef __GNUC__
    #ifndef PAR_UNUSED
      /* GCC's way to tell the compiler that a function parameter is not used */
      #define PAR_UNUSED(p) p __attribute__ ((unused))
    #endif

    #ifndef EXPECT_TRUE
      #define EXPECT_TRUE(cond) (__builtin_expect((cond), 1))
    #endif
    #ifndef EXPECT_FALSE
      #define EXPECT_FALSE(cond) (__builtin_expect((cond), 0))
    #endif

    #ifndef NORETURN
      #define NORETURN __attribute__ ((noreturn))
    #endif

    #ifndef static_assert
      #define static_assert(e, msg) extern int static_assert_dummy_[(e)?1:-1] __attribute__ ((unused))
    #endif
  #endif  /* __GNUC__ */

  #ifndef HAVE_WELL_DEFINED_PTR_CMP
    /* Check for known architectures with flat address spaces */
    #if defined __i386__ || defined _M_IX86 || defined __x86_64__
      #define HAVE_WELL_DEFINED_PTR_CMP 1
    #endif
  #endif
#endif


/*
 * Verification of the environment suitability
 */
#if !defined INTMAX_MIN || !defined INTMAX_MAX || !defined UINTMAX_MAX || \
    !defined SIZE_MAX || !defined PTRDIFF_MIN || !defined PTRDIFF_MAX
  #error C99-compliant <stdint.h> needed
#endif
#if (CHAR_BIT != 8) || (SCHAR_MIN != -128) \
                    || (SHRT_MIN + 1 != -SHRT_MAX) \
                    || (INT_MIN + 1 != -INT_MAX) \
                    || (LONG_MIN + 1 != -LONG_MAX) \
                    || (LLONG_MIN + 1 != -LLONG_MAX) \
                    || (INTMAX_MIN + 1 != -INTMAX_MAX)
  #error Only 8-bits-per-byte twos-complement environments are supported
#endif


/*
 * Default values for configuration macros
 */
 
/* Define to 1 if pointers to different objects can be compared reliably,
 * 0 otherwise.  Default 1 on known good platforms, 0 otherwise. */
#ifndef HAVE_WELL_DEFINED_PTR_CMP
  #define HAVE_WELL_DEFINED_PTR_CMP 0
#endif

/* Compiler's idea of a static inline function definition prefix */
#ifndef STATIC_INLINE
  #define STATIC_INLINE static inline
#endif

#ifndef NORETURN
  #define NORETURN
#endif

/* An implementation-specific way, if available, to tell the compiler
 * that a function parameter is unused.  By default expands to just its parameter. */
#ifndef PAR_UNUSED
  #define PAR_UNUSED(p) p
#endif

/* If the implementation provides a way to tell the compiler that a particular
 * condition is expected to be true or false, these two macros can be defined
 * to exploit that feature.  Their value is their argument, which for maximum
 * portability should always be a boolean expression.
 * By default they expand to just their argument.
 */
#ifndef EXPECT_TRUE
  #define EXPECT_TRUE(cond) cond
#endif
#ifndef EXPECT_FALSE
  #define EXPECT_FALSE(cond) cond
#endif

/*
 * Convenience macros
 */

#ifndef static_assert
  #define static_assert(e, msg) extern int static_assert_dummy_[(e)?1:-1]
#endif

#define static_assert1(e) static_assert(e, #e)

/* Align value `v` down to an integer multiple of `a`.
 * `a` must be an integer power of 2. */
#define ALIGN_DOWN(v, a) ((v) & ~((a) - 1))
/* Align value `v` up to an integer multiple of `a`.
 * `a` must be an integer power of 2.  It is evaluated twice. */
#define ALIGN_UP(v, a) ALIGN_DOWN((v) + ((a) - 1), a)

/* Number of elements in an array */
#define ARRAY_LEN(a) (sizeof(a)/sizeof((a)[0]))

#endif /* CFG_H */
