/*
 * myassert.h - Custom assertion macro support
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

#ifndef MYASSERT_H_
#define MYASSERT_H_

#include "cfg.h"

// Assertion level definitions (from lowest to highest)
#define ASSERT_LEVEL_NONE       -1
#define ASSERT_LEVEL_CRITICAL   0       // checks that should always be performed
#define ASSERT_LEVEL_NORMAL     1       // normal checks
#define ASSERT_LEVEL_THOROUGH   2       // checks that are expensive enough to be skipped
#define ASSERT_LEVEL_ALL        255

#ifndef ASSERT_LEVEL
#define ASSERT_LEVEL NORMAL
#endif

// Assertion level names -- prevent their accidental redefinitions
#define NONE        NONE
#define CRITICAL    CRITICAL
#define NORMAL      NORMAL
#define THOROUGH    THOROUGH
#define ALL         ALL

// helper macros
#define ASSERT_LEVEL_VAL_(name) ASSERT_LEVEL_ ## name
#define ASSERT_LEVEL_VAL_X_(macro) ASSERT_LEVEL_VAL_(macro)

// Check the assertion level
#define IS_ASSERT_LEVEL(test) \
            (ASSERT_LEVEL_VAL_X_(ASSERT_LEVEL) >= ASSERT_LEVEL_VAL_(test))

/*
 * The internal error function.
 * Usually, it will be called via the custom assertion macros defined below,
 * not directly.
 */
NORETURN void InternalError(const char *assertion, const char *extra_msg,
                            const char *file_name, const char *function_name,
                            long line_no);

#undef assert
/*
 * Custom assertion macros.
 * Unfortunately, we cannot use a single variable-argument macro if we want
 * to capture the original expression as a string.
 */
#define assert3(level, expr, msg) \
            (IS_ASSERT_LEVEL(level) && EXPECT_FALSE(!(expr)) \
                ? InternalError(#expr, msg, __FILE__, __func__, __LINE__) \
                : (void)0)
#define assert2(expr, msg) \
            (IS_ASSERT_LEVEL(NORMAL) && EXPECT_FALSE(!(expr)) \
                ? InternalError(#expr, msg, __FILE__, __func__, __LINE__) \
                : (void)0)
#define assert(expr) \
            (IS_ASSERT_LEVEL(NORMAL) && EXPECT_FALSE(!(expr)) \
                ? InternalError(#expr, (char *)0, \
                                           __FILE__, __func__, __LINE__) \
                : (void)0)

// For use in assert macros
enum { Not_Implemented = 0, Must_Not_Get_Here = 0 };

#endif /* MYASSERT_H_ */
