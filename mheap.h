/*
 * mheap.h - custom heap with movable blocks
 *
 * Copyright 2012--2024 Marcin Grzegorczyk
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

#ifndef MHEAP_H_
#define MHEAP_H_

#include "cfg.h"
#include "myassert.h"

// Type of heap block sizes (an unsigned integer type not larger than size_t)
#ifndef tMHeapBlockSize
typedef uint32_t tMHeapBlockSize;
#endif

// Provide full block header (allowing backward walk) for allocated blocks?
// (wastes one unit of tMHeapBlockSize per allocation)
#ifndef MHEAP_USE_DOUBLE_LINKS
#   include "myassert.h"
#   if !HAVE_WELL_DEFINED_PTR_CMP || IS_ASSERT_LEVEL(NORMAL)
#       define MHEAP_USE_DOUBLE_LINKS true
#   else
#       define MHEAP_USE_DOUBLE_LINKS false
#   endif
#endif

// Clear free block links when removing free blocks?
// (can make debugging easier and prevent some attacks)
#ifndef MHEAP_CLEAR_FREEBLK_LINKS
#   include "myassert.h"
#   if IS_ASSERT_LEVEL(NORMAL)
#       define MHEAP_CLEAR_FREEBLK_LINKS true
#   else
#       define MHEAP_CLEAR_FREEBLK_LINKS false
#   endif
#endif

// Heap block alignment
#ifndef MHEAP_BLOCK_ALIGN
// By default try to figure out the strictest fundamental alignment of all
// object types using a structure type. This might not give the correct result
// on some platforms.
typedef struct {
  char c;
  union { intmax_t i; long double ld; void *op; void (*fp)(void); } u;
} tMHeapAlignGuessHlp_;
#   define MHEAP_MIN_DATA_ALIGN_ ((int)offsetof(tMHeapAlignGuessHlp_, u))
#   define MHEAP_BLOCK_ALIGN (MHEAP_MIN_DATA_ALIGN_ > 4 ? MHEAP_MIN_DATA_ALIGN_ : 4)
#endif


// Helper macros to align block sizes
#define MHeapAlignDown(size) ((size) & ~((size_t)MHEAP_BLOCK_ALIGN - 1u))
#define MHeapAlignUp(size) MHeapAlignDown((size) + (MHEAP_BLOCK_ALIGN - 1u))


/*
 * Various useful minima and maxima.
 * To avoid having to expose internal structures here, we define a couple of
 * macros that semi-conservatively estimate sizes of the internal structures.
 * The implementation (.c) file uses static assertions to verify those values.
 */

// Auxiliary: heap allocation overhead estimate (upper bound)
#ifndef MHEAP_ALLOC_OVERHEAD_UB
#define MHEAP_ALLOC_OVERHEAD_UB (2*sizeof(tMHeapBlockSize))
#endif

// Auxiliary: heap segment overhead estimate (upper bound)
#ifndef MHEAP_SEG_OVERHEAD_UB
#define MHEAP_SEG_OVERHEAD_UB MHeapAlignUp(sizeof(void *) + 2*sizeof(size_t) \
                                           + 6*sizeof(tMHeapBlockSize))
#endif

// Auxiliary: heap segment minimum usable size estimate (upper bound)
#ifndef MHEAP_SEG_USE_MIN_UB
#define MHEAP_SEG_USE_MIN_UB \
                MHeapAlignUp(MHEAP_ALLOC_OVERHEAD_UB + 3*sizeof(void *))
#endif

// Auxiliary: heap segment usable size upper bound
#if SIZE_MAX > PTRDIFF_MAX
#define MHEAP_SEG_USE_UB_ PTRDIFF_MAX
#else
#define MHEAP_SEG_USE_UB_ (SIZE_MAX - MHEAP_SEG_OVERHEAD_UB)
#endif

// Maximum supported allocation size estimate (lower bound)
#define MHEAP_ALLOC_SUPP_MAX \
                (MHeapAlignDown((tMHeapBlockSize)\
                                (MHEAP_SEG_USE_UB_ < (tMHeapBlockSize)-1 \
                                        ? MHEAP_SEG_USE_UB_ : -1)) \
                                    - MHEAP_ALLOC_OVERHEAD_UB)

// Minimum heap segment total size estimate (upper bound)
#define MHEAP_SEG_SIZE_SUPP_MIN (MHEAP_SEG_OVERHEAD_UB + MHEAP_SEG_USE_MIN_UB)

// Heap state data size estimate (upper bound)
#ifndef MHEAP_STATE_SIZE_UB
#define MHEAP_STATE_SIZE_UB \
                (8*sizeof(void *) + 2*sizeof(tMHeapBlockSize) + 2*sizeof(int))
#endif


/*
 * Default heap parameters
 */

// Default preferred minimum size for new segments
#ifndef MHEAP_DEF_PREF_SEG_SIZE_NEW
#define MHEAP_DEF_PREF_SEG_SIZE_NEW 16384
#endif

// Default preferred segment size increase step
#ifndef MHEAP_DEF_PREF_SEG_SIZE_INC
#define MHEAP_DEF_PREF_SEG_SIZE_INC 4096
#endif


/*
 * Other types
 */

// Heap handle type
typedef struct mheapstate *tMHeapHandle;

// Invalid handle value
#define MHEAP_INVALID_HANDLE ((tMHeapHandle)0)

/* Heap walk callback procedure prototype.
 * Returns: true = continue walk, false = stop walk
 */
typedef bool tMHeapWalkProc(
        void *ptr,      // ->  allocated block (user part)
        size_t size,    // size of the block (without header)
        void *context); // context pointer passed to MHeapWalk()

/* Block post-movement callback procedure prototype.
 * Parameter: new pointer to the allocated block (user part)
 */
typedef void tMHeapBlkPostMoveProc(void *ptr);

/* Heap segment resize procedure prototype.
 * If such a procedure is available, it must not change the segment's base.
 * Returns: on success: new actual segment size (may be larger than requested)
 *          on failure: 0
 */
typedef size_t tMHeapSegResizeProc(
        void *segbase,      // -> segment base
        size_t oldsize,     // current segment's allocation size
        size_t newsize);    // new allocation size requested (always nonzero)

/* Heap segment (re)allocation procedure prototype.
 * Returns: on success: new segment base pointer
 *          on failure: NULL (`*p_segsize` unchanged)
 *          unspecified if (newsize == 0)
 */
typedef void *tMHeapSegReallocProc(
        void *segbase,                  // -> segment base; NULL = allocate new segment
        size_t * restrict p_segsize,    // -> in: current allocation size;
                                        //    out: new allocation size (may be larger than requested)
                                        //         unspecified if (newsize == 0)
        size_t newsize);                // new allocation size requested; 0 = free the segment

// Heap management policy flags
#define MHEAP_POLICY_ALLOC_HIGH         0x0001  // allocate in the high part of a free block
#define MHEAP_POLICY_CONSERVE_MEMORY    0x0010  // prefer defragmenting segments to allocating more memory
#define MHEAP_POLICY_AVOID_SEG_REALLOC  0x0020  // allocate new segment rather than reallocate existing one
#define MHEAP_POLICY_KEEP_FREE_SEG      0x0100  // do not deallocate empty segments
#define MHEAP_POLICY_NO_BLOCK_MOVEMENT  0x1000  // do not move blocks (no defragmentation or reallocation)

// Heap parameters structure
struct mheap_par {
    // Pointer to the segment resize callback; NULL if not available
    tMHeapSegResizeProc *seg_resize_proc;
    // Pointer to the segment (re)allocation callback; NULL if not available
    tMHeapSegReallocProc *seg_realloc_proc;
    /* Pointer to the block post-movement callback.
     *
     * If not NULL, the heap is defragmentable; a call to any of the allocation
     * functions may result in any block's address being changed.
     *
     * If NULL, block addresses can change only as a result of a call
     * to MHeapRealloc() or MHeapReallocEx(), and the segment (re)allocation
     * callback, if available, will be used only to allocate new segments
     * or free unused ones.
     */
    tMHeapBlkPostMoveProc *blk_post_move_proc;
    // Preferred minimum size for newly allocated segments
    tMHeapBlockSize pref_min_seg_size;
    // Preferred segment size increase step
    tMHeapBlockSize pref_seg_size_inc;
    // Heap management policy flags (MHEAP_POLICY_*)
    unsigned policy_flags;
};

// Default initializer for struct mheap_par
#define MHEAP_PAR_DEFAULT_INIT { \
                .pref_min_seg_size = MHEAP_DEF_PREF_SEG_SIZE_NEW, \
                .pref_seg_size_inc = MHEAP_DEF_PREF_SEG_SIZE_INC }


/*
 * Functions (see mheap.c for descriptions)
 */
bool MHeapIsValidPtr(tMHeapHandle heap_handle, const void *ptr);
bool MHeapWalk(tMHeapHandle heap_handle,
               tMHeapWalkProc *walk_proc,
               void *context);
void *MHeapAlloc(tMHeapHandle heap_handle, size_t size);
void *MHeapAllocEx(tMHeapHandle heap_handle, size_t size, unsigned flags);
void *MHeapResize(tMHeapHandle heap_handle, void *p_blk, size_t size);
void *MHeapRealloc(tMHeapHandle heap_handle, void *p_blk, size_t size);
void *MHeapReallocEx(tMHeapHandle heap_handle,
                     void *p_blk,
                     size_t size,
                     unsigned flags);
void MHeapFree(tMHeapHandle heap_handle, void *p_blk);
void MHeapFreeEx(tMHeapHandle heap_handle, void *p_blk, unsigned flags);
tMHeapBlockSize MHeapGetSize(tMHeapHandle heap_handle, const void *p_blk);
tMHeapHandle MHeapInit(void *base,
                       size_t init_size,
                       const struct mheap_par * restrict par);
bool MHeapDestroy(tMHeapHandle heap_handle);
void MHeapShrink(tMHeapHandle heap_handle);
bool MHeapDefrag(tMHeapHandle heap_handle);
void MHeapGetParameters(tMHeapHandle heap_handle,
                        struct mheap_par * restrict par);
void MHeapSetParameters(tMHeapHandle heap_handle,
                        const struct mheap_par * restrict par);

#endif /* MHEAP_H_ */
