/*
 * mheap.c - custom heap with movable blocks
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
 *
 * ---------------------------------------------------------------------------
 *
 * This implementation borrows some ideas from Doug Lea's dlmalloc;
 * however, it is conceptually much simpler (e.g. no free block binning)
 * and also adds some functionality of its own.
 */

#include "cfg.h"

#include <string.h>

#include "mheap.h"


// mheap.h sanity checks
static_assert((tMHeapBlockSize)-1 > 0,
              "tMHeapBlockSize must be an unsigned integer type!");
static_assert((tMHeapBlockSize)-1 <= SIZE_MAX,
              "tMHeapBlockSize must not be larger than size_t!");
static_assert1(MHEAP_BLOCK_ALIGN >= 4);
static_assert(!(MHEAP_BLOCK_ALIGN & (MHEAP_BLOCK_ALIGN - 1)),
              "MHEAP_BLOCK_ALIGN must be an integer power of 2");


/*
 * Full block header.
 * The header immediately precedes the block.  If the block is free
 * or MHEAP_USE_DOUBLE_LINKS is true, there is a full block header,
 * otherwise there is only the `head` field and the rest is available
 * to the previous block's user.
 * Segment boundary sentinels pretend to be allocated blocks with the size equal
 * to 0 (actual blocks always have at least the size of the header).
 */
struct mheapblkhdr {
    tMHeapBlockSize prev;       // size of the previous block, if free or if MHEAP_USE_DOUBLE_LINKS is true
    tMHeapBlockSize head;       // size of the current block + flags (MHEAPBLK_FLAG_*)
};

// Block header flags
#define MHEAPBLK_FLAG_PINUSE   ((tMHeapBlockSize)1) // previous block is allocated
#define MHEAPBLK_FLAG_CINUSE   ((tMHeapBlockSize)2) // current block is allocated

#define MHEAPBLK_SIZE_MASK (~(MHEAPBLK_FLAG_PINUSE | MHEAPBLK_FLAG_CINUSE))

static_assert1((MHEAP_BLOCK_ALIGN & MHEAPBLK_SIZE_MASK) == MHEAP_BLOCK_ALIGN);

/*
 * Heap segment descriptor.
 * For segments allocated using the (re)allocation callback (see below),
 * this structure is placed at the start of a segment (i.e. `base_offset` is 0),
 * except possibly for the segment that holds the heap state.
 * If `base_offset` is nonzero, the segment will not be reallocated, but it may
 * be resized (unless the segment has been provided externally).
 */
struct mheapsegment {
    // -> next segment, NULL if none
    struct mheapsegment *next;
    // Offset of this structure from the start of the allocated space;
    // MHEAPSEG_BASEOFFSET_EXTERN if the segment has been provided externally
    size_t base_offset;
    // Total size of the segment's allocated space
    size_t alloc_size;
    // Segment useful size (excluding segment descriptor and first block header)
    tMHeapBlockSize size;
    // Total bytes (including overhead) in free blocks in this segment
    tMHeapBlockSize total_free;
    // Number of free blocks in this segment
    tMHeapBlockSize n_freeblks;
    // Number of allocated blocks in this segment
    tMHeapBlockSize n_usedblks;
};

/* Offset to the first block from the segment descriptor
 */
#define MHEAP_SEG_FIRST_BLK_OFFSET MHeapAlignUp(sizeof(struct mheapsegment) \
                                                + sizeof(struct mheapblkhdr))

// Auxiliary: block size upper bound
#if SIZE_MAX > PTRDIFF_MAX
#define MHEAP_BLKSIZE_UBOUND_ PTRDIFF_MAX
#else
#define MHEAP_BLKSIZE_UBOUND_ (SIZE_MAX - MHEAP_SEG_FIRST_BLK_OFFSET)
#endif

// Single allocation overhead
#if MHEAP_USE_DOUBLE_LINKS
#define MHEAP_ALLOC_OVERHEAD sizeof(struct mheapblkhdr)
#else
#define MHEAP_ALLOC_OVERHEAD (sizeof(struct mheapblkhdr) \
                              - offsetof(struct mheapblkhdr, head))
#endif

// Maximum possible single allocation size
#define MHEAP_ALLOC_MAX \
                (MHeapAlignDown((tMHeapBlockSize)( \
                        MHEAP_BLKSIZE_UBOUND_ < (tMHeapBlockSize)-1 ? \
                            MHEAP_BLKSIZE_UBOUND_ : -1)) \
                    - MHEAP_ALLOC_OVERHEAD)

static_assert1(MHEAP_ALLOC_MAX >= MHEAP_ALLOC_SUPP_MAX);

/* Total segment overhead =
 *  offset to the first block + allocation overhead
 */
#define MHEAP_SEG_OVERHEAD (MHEAP_SEG_FIRST_BLK_OFFSET + MHEAP_ALLOC_OVERHEAD)

/* Special value of (struct mheapsegment).base_offset for externally allocated
 * segments
 */
#define MHEAPSEG_BASEOFFSET_EXTERN ((size_t)-1)

// Assertions
#define mheap_assert(expr) \
            (IS_ASSERT_LEVEL(NORMAL) && EXPECT_FALSE(!(expr)) \
                ? InternalError(#expr, "Heap corrupted", \
                                __FILE__, __func__, __LINE__) \
                : (void)0)
#define mheap_assert_par(expr) \
            (IS_ASSERT_LEVEL(NORMAL) && EXPECT_FALSE(!(expr)) \
                ? InternalError(#expr, "Wrong parameter or heap corrupted", \
                                __FILE__, __func__, __LINE__) \
                : (void)0)

/*
 * Free block link structure
 */
struct mheapfreeblklink {
    struct mheapfreeblklink *prev, *next;
};

/*
 * Free block payload.  Free blocks form a circular doubly-linked list,
 * except for blocks smaller than MHEAP_FREEBLKSIZE_MIN, which are not tracked.
 */
struct mheapfreeblk {
    struct mheapfreeblklink link;
    struct mheapsegment *seg;           // -> segment to which this block belongs
};

// Smallest possible block size
#define MHEAP_BLKSIZE_MIN MHeapAlignUp(sizeof(struct mheapblkhdr))

// Smallest possible free block size on the list
#define MHEAP_FREEBLKSIZE_MIN MHeapAlignUp(sizeof(struct mheapblkhdr) + \
                                           sizeof(struct mheapfreeblk))

static_assert1(MHEAP_BLKSIZE_MIN >= MHEAP_ALLOC_OVERHEAD);
static_assert1(MHEAP_FREEBLKSIZE_MIN >= MHEAP_BLKSIZE_MIN);

// Largest possible block size
#define MHEAP_BLKSIZE_MAX (MHEAP_ALLOC_MAX + MHEAP_ALLOC_OVERHEAD)

static_assert(MHEAP_BLKSIZE_MAX > MHEAP_ALLOC_MAX, "Overflow!");
static_assert(MHEAP_BLKSIZE_MAX <= (tMHeapBlockSize)-1, "MHEAP_BLKSIZE_MAX "
                  "must be representable in type tMHeapBlockSize");

// Minimum possible segment size (excluding descriptor and first block header)
#define MHEAP_SEG_SIZE_MIN MHEAP_FREEBLKSIZE_MIN

// Maximum possible segment size (excluding descriptor and first block header)
#define MHEAP_SEG_SIZE_MAX MHEAP_BLKSIZE_MAX

// Smallest supported total segment size (including overhead)
#define MHEAP_SEG_TOTAL_SIZE_MIN \
                (MHEAP_SEG_FIRST_BLK_OFFSET + MHEAP_SEG_SIZE_MIN)

// Largest supported total segment size = maximum allocation + segment overhead
#define MHEAP_SEG_TOTAL_SIZE_MAX \
                (MHEAP_SEG_FIRST_BLK_OFFSET + MHEAP_SEG_SIZE_MAX)

static_assert(MHEAP_SEG_TOTAL_SIZE_MAX > MHEAP_SEG_SIZE_MAX, "Overflow!");

static_assert1(MHEAP_SEG_TOTAL_SIZE_MIN > MHEAP_SEG_OVERHEAD);
static_assert1(MHEAP_SEG_TOTAL_SIZE_MIN < MHEAP_SEG_TOTAL_SIZE_MAX);
static_assert1(MHEAP_SEG_SIZE_SUPP_MIN >= MHEAP_SEG_TOTAL_SIZE_MIN);
static_assert1(MHEAP_SEG_TOTAL_SIZE_MIN < MHEAP_SEG_SIZE_MAX);


/*
 * Heap state block.
 *
 * If both `seg_resize_proc` and `seg_realloc_proc` are NULL, the heap cannot
 * grow.
 */
struct mheapstate {
    // Header and sentinel of the circular doubly-linked free block list
    struct mheapfreeblklink freeblkh;
    // Pointer to the segment list; NULL if no segments yet
    struct mheapsegment *seglist;
    // Pointer to the segment resize callback; NULL if not available
    tMHeapSegResizeProc *seg_resize_proc;
    // Pointer to the segment (re)allocation callback; NULL if not available
    tMHeapSegReallocProc *seg_realloc_proc;
    // Pointer to the block post-movement callback.
    // If NULL, then blocks are not movable.
    tMHeapBlkPostMoveProc *blk_post_move_proc;
    // Temporary pointer to a tracked block (used during reallocation)
    // NULL if no block is currently tracked
    void *p_tracked_block;
    // Size of the allocated space containing this state block
    // 0 if this state block has not been allocated with the callback
    size_t alloc_size;
    // Preferred minimum new segment size
    tMHeapBlockSize pref_min_seg_size;
    // Preferred segment size increase step
    tMHeapBlockSize pref_seg_size_inc;
    // Heap management policy flags
    unsigned policy_flags;
    // Number of segments
    unsigned short n_segments;
};

static_assert1(MHEAP_STATE_SIZE_UB >= sizeof(struct mheapstate));

#define MHEAP_STATE_SIZE_ALIGNED MHeapAlignUp(sizeof(struct mheapstate))


/******************************************************************************
 * Helper macros/functions for heap data access
 ******************************************************************************/

/*
 * Note: the subexpressions involving `(void)sizeof` are there to ensure
 * a compiler diagnostic if the argument is of wrong type, and have no effect
 * otherwise.
 */

/* True if size/offset is aligned
 */
#define MHeapIsAligned(size) (!((size) & (MHEAP_BLOCK_ALIGN - 1u)))

/* Get pointer to the segment's first block
 */
#define MHeapGetSegFirstBlk(p_seg) \
                ((void)sizeof((p_seg) > (struct mheapsegment *)0), \
                (void *)((char *)p_seg + MHEAP_SEG_FIRST_BLK_OFFSET))


/* Get pointer to the end of segment
 */
STATIC_INLINE void *MHeapGetSegEnd(const struct mheapsegment *p_seg)
{
    return (char *)MHeapGetSegFirstBlk(p_seg) + p_seg->size;
}


/* Convert block head pointer to block header pointer
 */
#define MHeapBlkHeadToBlkHdrPtr(p_blkhead) \
                ((void)sizeof((p_blkhead) > (tMHeapBlockSize *)0), \
                (struct mheapblkhdr *)((char *)(p_blkhead) \
                        - offsetof(struct mheapblkhdr, head)))

/* Convert block header pointer to block payload pointer
 */
#define MHeapBlkHdrToBlkPtr(p_blkhdr) \
                ((void)sizeof((p_blkhdr) > (struct mheapblkhdr *)0), \
                (void *)((char *)(p_blkhdr) + sizeof(struct mheapblkhdr)))

/* Convert block head pointer to block payload pointer
 */
#define MHeapBlkHeadToBlkPtr(p_blkhead) \
                MHeapBlkHdrToBlkPtr(MHeapBlkHeadToBlkHdrPtr(p_blkhead))

/* Convert block payload pointer to block header pointer
 */
#define MHeapBlkToBlkHdrPtr(p_blk) \
                ((struct mheapblkhdr *)((char *)(p_blk) \
                        - sizeof(struct mheapblkhdr)))

/* Get pointer to the segment's first block's header
 */
#define MHeapGetSegFirstBlkHdr(p_seg) \
                MHeapBlkToBlkHdrPtr(MHeapGetSegFirstBlk(p_seg))

/* Get pointer to the end-of-segment (sentinel) block's header
 */
#define MHeapGetSegEndBlkHdr(p_seg) MHeapBlkToBlkHdrPtr(MHeapGetSegEnd(p_seg))

/* True if the pointer points within the specified range; otherwise, false
 * if HAVE_WELL_DEFINED_PTR_CMP is true; otherwise may cause undefined behaviour
 * on some systems (OK if used in assertions).
 * `base` and `ptr` are evaluated more than once
 */
#define MHEAP_IS_PTR_IN_RANGE(base, size, ptr) \
                ((char *)(ptr) >= (char *)(base) \
                        && (char *)(ptr) < (char *)(base) + (size))

/* True if the pointer points within the specified segment; otherwise, false
 * if HAVE_WELL_DEFINED_PTR_CMP is true; otherwise may cause undefined behaviour
 * on some systems (OK if used in assertions).
 * `p_seg` and `ptr` are evaluated more than once
 */
#define MHEAP_IS_PTR_IN_SEGMENT(p_seg, ptr) \
                MHEAP_IS_PTR_IN_RANGE(MHeapGetSegFirstBlk(p_seg), \
                                      (p_seg)->size, ptr)


/******************************************************************************
 * Basic heap management
 ******************************************************************************/

/* Auxiliary: callback passed to MHeapWalk() by MHeapAssertConsistency()
 *
 * See the definition of `tMHeapWalkProc` for details.
 */
static bool MHeapWalkCB_Continue(PAR_UNUSED(void *ptr),
                                 PAR_UNUSED(size_t size),
                                 PAR_UNUSED(void *context))
{
    return true;
}


/* Check heap consistency
 *
 * Does not return (causes assertion failure) if the check fails
 */
static void MHeapAssertConsistency(tMHeapHandle heap_handle)
{
    if (IS_ASSERT_LEVEL(THOROUGH)) {
        bool walk_ok = MHeapWalk(heap_handle, MHeapWalkCB_Continue, NULL);
        assert(walk_ok);
    }
}


/*
 * Auxiliary structure used by MHeapIsValidPtr() and MHeapAssertValidPtr()
 */
struct mheap_validation {
    const void *blk_address;    // in: address of the block to search for
    bool continue_when_found;   // in: false = stop walk when found, true = check whole heap regardless
    bool is_valid;              // out: true if `blk_address` is valid, otherwise unchanged
};


/* Auxiliary: callback passed to MHeapWalk() by MHeapIsValidPtr()
 * and MHeapAssertValidPtr()
 *
 * See the definition of `tMHeapWalkProc` for details.
 */
static bool MHeapWalkCB_IsValidPtr(void *ptr,
                                   PAR_UNUSED(size_t size),
                                   void *context)
{
    struct mheap_validation *p_data = context;

    if (ptr == p_data->blk_address) {
        p_data->is_valid = true;
        return p_data->continue_when_found;
    }

    return true;
}


/* Check heap consistency & whether a pointer points to an allocated block
 *
 * Does not return (causes assertion failure) if either check fails
 */
static void MHeapAssertValidPtr(tMHeapHandle heap_handle, const void *ptr)
{
    if (IS_ASSERT_LEVEL(THOROUGH)) {
        struct mheap_validation vdata = {
            .blk_address = ptr,
            .continue_when_found = true,
            .is_valid = false
        };

        bool walk_ok = MHeapWalk(heap_handle, MHeapWalkCB_IsValidPtr, &vdata);
        assert(walk_ok);
        assert2(vdata.is_valid, "Heap corrupted");
    }
}


/* Check if a pointer points to an allocated block
 *
 * Returns: true/false
 */
bool MHeapIsValidPtr(tMHeapHandle heap_handle, const void *ptr)
{
    struct mheap_validation vdata = {
        .blk_address = ptr,
        .continue_when_found = false,
        .is_valid = false
    };

    bool found = !MHeapWalk(heap_handle, MHeapWalkCB_IsValidPtr, &vdata);
    assert(vdata.is_valid == found);

    return found;
}


/* Walk a custom heap, calling the user-specified procedure
 * for every allocated block found
 *
 * If ASSERT_LEVEL is NORMAL or higher, checks the heap consistency as well,
 * using the mheap_assert() macro.
 *
 * Returns: true = completed normally
 *          false = stopped because the callback returned false
 */
bool MHeapWalk(
        tMHeapHandle heap_handle,       // heap handle
        tMHeapWalkProc *walk_proc,      // -> callback
        void *context)                  // parameter passed to the callback
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    const struct mheapstate *heap_state = heap_handle;

    unsigned short n_segments_left = heap_state->n_segments;
    for (const struct mheapsegment *p_seg = heap_state->seglist;
            p_seg; p_seg = p_seg->next) {
        const tMHeapBlockSize *p_blkhead = &MHeapGetSegFirstBlkHdr(p_seg)->head;
        mheap_assert(p_seg->size >= MHEAP_SEG_SIZE_MIN);
        mheap_assert(p_seg->size <= MHEAP_SEG_SIZE_MAX);
        size_t size_remain = p_seg->size;
        bool pinuse = true;

        do {
            mheap_assert((*p_blkhead & MHEAPBLK_FLAG_PINUSE) == pinuse);

            tMHeapBlockSize blksize = *p_blkhead & MHEAPBLK_SIZE_MASK;
            bool cinuse = *p_blkhead & MHEAPBLK_FLAG_CINUSE;
            if (EXPECT_FALSE(blksize == 0)) {
                mheap_assert(cinuse);
                mheap_assert(size_remain == 0);
                break;
            }

            mheap_assert(MHeapIsAligned(blksize));
            mheap_assert(blksize >= MHEAP_BLKSIZE_MIN);
            mheap_assert(blksize <= MHEAP_BLKSIZE_MAX);
            mheap_assert(blksize <= size_remain);

            const tMHeapBlockSize *p_nextblkhead =
                    (tMHeapBlockSize *)((char *)p_blkhead + blksize);
            const struct mheapblkhdr *p_nextblkhdr =
                    MHeapBlkHeadToBlkHdrPtr(p_nextblkhead);

            if (EXPECT_TRUE(cinuse)) {
#if MHEAP_USE_DOUBLE_LINKS
                mheap_assert(p_nextblkhdr->prev == blksize);
#endif
                void *p_blk = MHeapBlkHeadToBlkPtr(p_blkhead);
                if (!walk_proc(p_blk, blksize - MHEAP_ALLOC_OVERHEAD, context))
                    return false;
            } else {
                mheap_assert(p_nextblkhdr->prev == blksize);
                if (blksize >= MHEAP_FREEBLKSIZE_MIN) {
                    struct mheapfreeblk *p_freeblk =
                            MHeapBlkHeadToBlkPtr(p_blkhead);
                    mheap_assert(p_freeblk->seg == p_seg);
                }
            }

            p_blkhead = p_nextblkhead;
            pinuse = cinuse;
            size_remain -= blksize;
        } while (true);  // exit condition inside the loop

        n_segments_left--;
    }

    assert(n_segments_left == 0);
    return true;
}


/* Figure out the segment a block belongs to
 *
 * Execution of this function may involve scanning blocks until the beginning
 * or the end of the containing segment.
 *
 * Returns: pointer to segment descriptor
 */
static struct mheapsegment *MHeapGetBlockSegment(
        const struct mheapstate * restrict heap_state,
        const void * restrict p_blk)
{
    assert(heap_state->n_segments > 0);

    const struct mheapsegment * restrict p_seg = heap_state->seglist;
    assert(p_seg != NULL);

    /*
     * If there is only one segment, the answer is obvious.
     */

    if (heap_state->n_segments <= 1) {
        assert(p_seg->next == NULL);
        mheap_assert_par(MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_blk));
        return (struct mheapsegment *)p_seg;  // need to cast const away
    }

    /*
     * If either the specified block or its predecessor is free and large enough
     * to have an embedded segment pointer, we can use it.
     */

    const struct mheapfreeblk *p_freeblk = NULL;

    const struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;

    mheap_assert_par(MHeapIsAligned(blksize));
    mheap_assert_par(blksize >= MHEAP_BLKSIZE_MIN);
    mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);
    const struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);

    bool cinuse = p_blkhdr->head & MHEAPBLK_FLAG_CINUSE;
    bool pinuse = p_blkhdr->head & MHEAPBLK_FLAG_PINUSE;
    if (!cinuse && blksize >= MHEAP_FREEBLKSIZE_MIN) {
        // this block is free and large enough
        mheap_assert_par(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
        mheap_assert_par(p_nextblkhdr->prev == blksize);

        p_freeblk = p_blk;
        return p_freeblk->seg;
    } else if (!pinuse && p_blkhdr->prev >= MHEAP_FREEBLKSIZE_MIN) {
        // previous block is free and large enough
        blksize = p_blkhdr->prev;
        mheap_assert_par(MHeapIsAligned(blksize));
        mheap_assert_par(blksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);
        p_freeblk = (struct mheapfreeblk *)((char *)p_blk - blksize);

        const tMHeapBlockSize *p_prevblkhead =
                &MHeapBlkToBlkHdrPtr(p_freeblk)->head;
        mheap_assert_par(!(*p_prevblkhead & MHEAPBLK_FLAG_CINUSE));
        mheap_assert_par((*p_prevblkhead & MHEAPBLK_SIZE_MASK) == blksize);

        return p_freeblk->seg;
    }

    /*
     * Otherwise, we'll use one of several methods to arrive at the segment.
     */

    // Variables for forward block scan
    const struct mheapblkhdr *p_blkhdr_f = p_blkhdr;
    tMHeapBlockSize blksize_f;
    bool cinuse_f = cinuse;
    bool pinuse_f = pinuse;
#if MHEAP_USE_DOUBLE_LINKS
    // Variables for backward block scan
    const struct mheapblkhdr *p_blkhdr_b = p_blkhdr;
    tMHeapBlockSize blksize_b;
    bool cinuse_b = cinuse;
    bool pinuse_b = pinuse;
#endif
    // Segment end pointer for the final segment search
    //  (performed only if HAVE_WELL_DEFINED_PTR_CMP is false)
    const void *p_segend = NULL;

    do {
#if HAVE_WELL_DEFINED_PTR_CMP
        /*
         * Method 1: Walk the segment list and check if the block is within a
         * segment.  This is usually the fastest method, but requires using
         * relational operators on pointers to unrelated objects, which does not
         * work in some environments (the C standard makes it undefined).
         */
        if (MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_blk)) {
            // That's the segment, Captain
            return (struct mheapsegment *)p_seg;  // need to cast const away
        } else {
            // continue scan
            p_seg = p_seg->next;
            mheap_assert_par(p_seg != NULL);
        }
#endif  // HAVE_WELL_DEFINED_PTR_CMP

        /*
         * Method 2: Walk the blocks until we either encounter a free block
         * with an embedded segment pointer, or reach the segment bounds.
         */

#if MHEAP_USE_DOUBLE_LINKS
        /*
         * Method 2a: If we can count on the `prev` field being always present,
         * we'll walk the blocks backwards as well as forwards.
         */
        blksize_b = p_blkhdr_b->prev;
        if (EXPECT_FALSE(blksize_b == 0)) {
            /*
             * We've reached the start of the segment.
             * The segment descriptor is at a fixed offset from there.
             */
            mheap_assert_par(pinuse_b);
            return (struct mheapsegment *)(
                    (char *)MHeapBlkHdrToBlkPtr(p_blkhdr_b)
                    - MHEAP_SEG_FIRST_BLK_OFFSET);
        }

        mheap_assert_par(MHeapIsAligned(blksize_b));
        mheap_assert_par(blksize_b >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(blksize_b <= MHEAP_BLKSIZE_MAX);

        p_blkhdr_b = (struct mheapblkhdr *)((char *)p_blkhdr_b - blksize_b);
        mheap_assert_par((p_blkhdr_b->head & MHEAPBLK_SIZE_MASK) == blksize_b);

        cinuse_b = p_blkhdr_b->head & MHEAPBLK_FLAG_CINUSE;
        mheap_assert_par(cinuse_b == pinuse_b);

        pinuse_b = p_blkhdr_b->head & MHEAPBLK_FLAG_PINUSE;

        if (!cinuse_b && blksize_b >= MHEAP_FREEBLKSIZE_MIN) {
            // We've found a free block large enough
            mheap_assert_par(pinuse_b);

            p_freeblk = MHeapBlkHdrToBlkPtr(p_blkhdr_b);
            break;
        }
#endif  // MHEAP_USE_DOUBLE_LINKS

        /*
         * Method 2b: Walk the blocks forwards
         */
        if (p_segend) {
            /*
             * We've already reached the end of the segment and now we're
             * scanning the segment list to see which segment it is the end of.
             * (Valid pointers can always be compared for equality.)
             * If HAVE_WELL_DEFINED_PTR_CMP is true, it makes no sense to do
             * that; the normal segment walk (method 1) will get to the segment
             * sooner, anyway.  In that case, if we've reached the end
             * of the segment, we just do nothing.
             */
#if !HAVE_WELL_DEFINED_PTR_CMP
            if (MHeapGetSegEnd(p_seg) == p_segend) {
                // That's the segment, Captain
                return (struct mheapsegment *)p_seg;  // need to cast const away
            } else {
                // continue scan
                p_seg = p_seg->next;
                mheap_assert_par(p_seg != NULL);
            }
#endif
        } else {
            p_blkhdr_f = p_nextblkhdr;
            blksize_f = p_blkhdr_f->head & MHEAPBLK_SIZE_MASK;
            pinuse_f = cinuse_f;
            mheap_assert_par((p_blkhdr_f->head & MHEAPBLK_FLAG_PINUSE)
                             == pinuse_f);

            cinuse_f = p_blkhdr_f->head & MHEAPBLK_FLAG_CINUSE;
            if (EXPECT_FALSE(blksize_f == 0)) {
                mheap_assert_par(cinuse_f);
                /*
                 * We've reached the end of the segment; initiate segment list
                 * scan (see above).  If HAVE_WELL_DEFINED_PTR_CMP is false,
                 * then `p_seg` still points to the first segment.
                 */
                p_segend = MHeapBlkHdrToBlkPtr(p_blkhdr_f);
            }

            mheap_assert_par(MHeapIsAligned(blksize_f));
            mheap_assert_par(blksize_f >= MHEAP_BLKSIZE_MIN);
            mheap_assert_par(blksize_f <= MHEAP_BLKSIZE_MAX);
            p_nextblkhdr =
                    (struct mheapblkhdr *)((char *)p_blkhdr_f + blksize_f);
            if (!cinuse_f && blksize_f >= MHEAP_FREEBLKSIZE_MIN) {
                // We've found a free block large enough
                mheap_assert_par(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
                mheap_assert_par(p_nextblkhdr->prev == blksize_f);

                p_freeblk = MHeapBlkHdrToBlkPtr(p_blkhdr_f);
                break;
            }
        }
    } while (true);  // exit condition inside the loop

    /*
     * We should get here only if we have found a free block large enough
     * to have an embedded segment pointer.
     */

    assert(p_freeblk != NULL);
    assert(!(MHeapBlkToBlkHdrPtr(p_freeblk)->head & MHEAPBLK_FLAG_CINUSE));
    assert((MHeapBlkToBlkHdrPtr(p_freeblk)->head & MHEAPBLK_SIZE_MASK)
           >= MHEAP_FREEBLKSIZE_MIN);

    return p_freeblk->seg;
}


/* Check if a block belongs to the segment
 *
 * Unlike the MHEAP_IS_PTR_IN_SEGMENT() macro, the result is always defined;
 * however, on some platforms this function might execute slowly.
 *
 * Returns: true = in segment, false = not in segment
 */
static bool MHeapIsBlockInSegment(
        PAR_UNUSED(const struct mheapstate * restrict heap_state),
        const struct mheapsegment * restrict p_seg,
        const void * restrict p_blk)
{
#if HAVE_WELL_DEFINED_PTR_CMP
    return MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_blk);
#else
    return (MHeapGetBlockSegment(heap_state, p_blk) == p_seg);
#endif
}


/* Check if the last block in a segment is free
 *
 * Returns: on success: pointer to the header of the final free block
 *                      of the segment
 *          on failure: NULL
 */
static struct mheapfreeblk *MHeapGetSegFinalFreeBlock(
        const struct mheapsegment * restrict p_seg)
{
    mheap_assert_par(p_seg->size >= MHEAP_SEG_SIZE_MIN);
    mheap_assert_par(p_seg->size <= MHEAP_SEG_SIZE_MAX);

    // get pointer to the end-of-segment sentinel
    struct mheapblkhdr *p_endblkhdr = MHeapGetSegEndBlkHdr(p_seg);
    assert(MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_endblkhdr));
    mheap_assert_par((p_endblkhdr->head & MHEAPBLK_SIZE_MASK) == 0);
    mheap_assert_par(p_endblkhdr->head & MHEAPBLK_FLAG_CINUSE);
    if (!(p_endblkhdr->head & MHEAPBLK_FLAG_PINUSE)) {
        // the last block is free
        struct mheapblkhdr *p_lastblkhdr =
                (struct mheapblkhdr *)((char *)p_endblkhdr - p_endblkhdr->prev);
        mheap_assert_par(
                MHEAP_IS_PTR_IN_SEGMENT(p_seg,
                                        MHeapBlkHdrToBlkPtr(p_lastblkhdr)));
        mheap_assert_par(!(p_lastblkhdr->head & MHEAPBLK_FLAG_CINUSE));
        mheap_assert_par((p_lastblkhdr->head & MHEAPBLK_SIZE_MASK)
                             == p_endblkhdr->prev);
        return MHeapBlkHdrToBlkPtr(p_lastblkhdr);
    } else {
        // the last block is allocated
        return NULL;
    }
}


/* Remove a free block from the free block list
 */
static void MHeapRemoveFreeBlockFromList(struct mheapfreeblk * restrict p_blk)
{
    // assert pointer validity
    const struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    mheap_assert_par(!(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE));
    tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    mheap_assert_par(MHeapIsAligned(blksize));
    mheap_assert_par(blksize >= MHEAP_FREEBLKSIZE_MIN);
    mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);
    const struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    mheap_assert_par(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
    mheap_assert_par(p_nextblkhdr->prev == blksize);

    // assert data structure validity
    mheap_assert_par(p_blk->link.next != NULL);
    mheap_assert_par(p_blk->link.prev != NULL);
    mheap_assert_par(p_blk->link.next != &p_blk->link);
    mheap_assert_par(p_blk->link.prev != &p_blk->link);
    mheap_assert_par(p_blk->link.next->prev == &p_blk->link);
    mheap_assert_par(p_blk->link.prev->next == &p_blk->link);

    // perform the operation
    struct mheapfreeblklink *nextlink = p_blk->link.next;
    struct mheapfreeblklink *prevlink = p_blk->link.prev;
    prevlink->next = nextlink;
    nextlink->prev = prevlink;
#if MHEAP_CLEAR_FREEBLK_LINKS
    p_blk->link.next = NULL;
    p_blk->link.prev = NULL;
#endif
}


/* Add a free block to the free block list
 */
static void MHeapAddFreeBlockToList(
        struct mheapstate *heap_state,
        struct mheapfreeblk * restrict p_blk,
        tMHeapBlockSize blksize)
{
    assert(MHeapIsAligned(blksize));
    assert(blksize >= MHEAP_FREEBLKSIZE_MIN);
    assert(blksize <= MHEAP_BLKSIZE_MAX);
    // assert pointer validity
    const struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    mheap_assert_par(!(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE));
    mheap_assert_par((p_blkhdr->head & MHEAPBLK_SIZE_MASK) == blksize);
    const struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    mheap_assert_par(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
    mheap_assert_par(p_nextblkhdr->prev == blksize);

    assert(heap_state->freeblkh.next != NULL);
    assert(heap_state->freeblkh.prev != NULL);

    /*
     * If the first free block in the list exists and is smaller than the block
     * being added, add at the end of the list, otherwise add at the beginning.
     */
    struct mheapfreeblklink *listprevlink, *listnextlink;
    if (heap_state->freeblkh.next != &heap_state->freeblkh
            && (MHeapBlkToBlkHdrPtr(heap_state->freeblkh.next)->head
                    & MHEAPBLK_SIZE_MASK) < blksize) {
        listprevlink = heap_state->freeblkh.prev;
    } else {
        listprevlink = &heap_state->freeblkh;
    }
    mheap_assert(listprevlink->prev->next = listprevlink);
    mheap_assert(listprevlink->next->prev = listprevlink);
    listnextlink = listprevlink->next;
    p_blk->link.prev = listprevlink;
    p_blk->link.next = listnextlink;
    listnextlink->prev = &p_blk->link;
    listprevlink->next = &p_blk->link;
}


/* Create a new free block at the specified address
 */
static void MHeapMakeFreeBlock(
        struct mheapstate *heap_state,
        struct mheapsegment * restrict p_seg,
        void * restrict p_blk,
        tMHeapBlockSize blksize)
{
    assert(MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_blk));
    assert(MHeapIsAligned(blksize));
    assert(blksize >= MHEAP_BLKSIZE_MIN);
    assert(blksize <= MHEAP_BLKSIZE_MAX);

    // previous block must be in use, otherwise we'd coalesce them
    MHeapBlkToBlkHdrPtr(p_blk)->head = blksize | MHEAPBLK_FLAG_PINUSE;

    struct mheapblkhdr *p_nextblkhdr =
            MHeapBlkToBlkHdrPtr((char *)p_blk + blksize);
    p_nextblkhdr->head &= ~MHEAPBLK_FLAG_PINUSE;
    p_nextblkhdr->prev = blksize;

    if (blksize >= MHEAP_FREEBLKSIZE_MIN) {
        struct mheapfreeblk *p_freeblk = p_blk;
        p_freeblk->seg = p_seg;
        MHeapAddFreeBlockToList(heap_state, p_freeblk, blksize);
    }

    p_seg->n_freeblks++;
    assert(p_seg->n_freeblks > 0);
}


/* Remove a free block
 */
static void MHeapKillFreeBlock(
        struct mheapsegment * restrict p_seg,
        struct mheapfreeblk * restrict p_blk)
{
    // assert pointer validity
    assert(MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_blk));

    const struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    mheap_assert_par(!(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE));

    tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    mheap_assert_par(MHeapIsAligned(blksize));
    mheap_assert_par(blksize >= MHEAP_BLKSIZE_MIN);
    mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);
    const struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    mheap_assert_par(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
    mheap_assert_par(p_nextblkhdr->prev == blksize);

    if (blksize >= MHEAP_FREEBLKSIZE_MIN) {
        mheap_assert_par(p_blk->seg == p_seg);
        MHeapRemoveFreeBlockFromList(p_blk);
    }

    assert(p_seg->n_freeblks > 0);
    p_seg->n_freeblks--;
}


/* Turn free block into partially or completely allocated block
 *
 * Returns: pointer to the allocated part
 */
static void *MHeapAllocFreeBlock(
        struct mheapstate *heap_state,
        struct mheapfreeblk * restrict p_blk,
        tMHeapBlockSize req_size,               // requested allocation size
        unsigned flags)                         // combination of MHEAP_POLICY_*
{
    assert(MHeapIsAligned(req_size));

    // assert pointer validity
    struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    mheap_assert_par(!(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE));
    mheap_assert_par(p_blkhdr->head & MHEAPBLK_FLAG_PINUSE);

    tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    mheap_assert_par(MHeapIsAligned(blksize));
    mheap_assert_par(blksize >= MHEAP_FREEBLKSIZE_MIN);
    mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);
    struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    mheap_assert_par(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
    mheap_assert_par(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE);
    mheap_assert_par(p_nextblkhdr->prev == blksize);

    struct mheapsegment * restrict p_seg = p_blk->seg;
    assert(MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_blk));

    tMHeapBlockSize rem_size = blksize - req_size;
    assert3(CRITICAL, rem_size <= blksize, "Wrong parameter or heap corrupted");
    if (rem_size < MHEAP_BLKSIZE_MIN) {
        // allocate the whole block
        req_size = blksize;
        rem_size = 0;
    }

    p_seg->n_usedblks++;
    assert(p_seg->n_usedblks > 0);
    assert(p_seg->total_free >= req_size);
    p_seg->total_free -= req_size;

    if ((flags & MHEAP_POLICY_ALLOC_HIGH) && rem_size) {
        // allocating high
        if (rem_size < MHEAP_FREEBLKSIZE_MIN) {
            // the remaining part is too small for a full free block
            // need to unlink the free block
            MHeapRemoveFreeBlockFromList(p_blk);
        }
        // otherwise, we only need to adjust the block size
        p_blkhdr->head = rem_size | MHEAPBLK_FLAG_PINUSE;
        p_nextblkhdr->head |= MHEAPBLK_FLAG_PINUSE;
#if MHEAP_USE_DOUBLE_LINKS
        p_nextblkhdr->prev = req_size;
#endif
        // now create the newly allocated block's header
        struct mheapblkhdr *p_splitblkhdr =
                (struct mheapblkhdr *)((char *)p_blkhdr + rem_size);
        p_splitblkhdr->prev = rem_size;
        p_splitblkhdr->head = req_size | MHEAPBLK_FLAG_CINUSE;
        return MHeapBlkHdrToBlkPtr(p_splitblkhdr);
    } else {
        // the current free block must go
        MHeapKillFreeBlock(p_seg, p_blk);

        struct mheapblkhdr *p_splitblkhdr =
                (struct mheapblkhdr *)((char *)p_blkhdr + req_size);

        if (rem_size > 0) {
            // make a free block in the remaining part
            MHeapMakeFreeBlock(heap_state,
                               p_seg,
                               MHeapBlkHdrToBlkPtr(p_splitblkhdr),
                               rem_size);
        }

        // make the block allocated
        p_blkhdr->head = req_size | MHEAPBLK_FLAG_CINUSE | MHEAPBLK_FLAG_PINUSE;
#if MHEAP_USE_DOUBLE_LINKS
        p_splitblkhdr->prev = req_size;
#endif
        return p_blk;
    }
}


/* Find either a free block with at least the specified size (including
 * overhead), or, failing that, the largest free block
 *
 * Returns: on success: pointer to the found block
 *          on failure (no free blocks): NULL
 */
static struct mheapfreeblk *MHeapFindFreeOrLargestBlock(
        const struct mheapstate *heap_state,
        tMHeapBlockSize req_size)
{
    assert(heap_state->freeblkh.next != NULL);
    assert(heap_state->freeblkh.prev != NULL);

    struct mheapfreeblk *p_largest_free_blk = NULL;
    tMHeapBlockSize largest_free_blksize = 0;

    struct mheapfreeblklink *blklink;
    for (blklink = heap_state->freeblkh.next; blklink != &heap_state->freeblkh;
            blklink = blklink->next) {
        mheap_assert(blklink->next != NULL);
        mheap_assert(blklink->prev != NULL);
        mheap_assert(blklink->next != blklink);
        mheap_assert(blklink->prev != blklink);
        mheap_assert(blklink->next->prev == blklink);
        mheap_assert(blklink->prev->next == blklink);

        struct mheapfreeblk *p_blk = (struct mheapfreeblk *)blklink;
        const struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
        mheap_assert(!(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE));

        tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
        mheap_assert(MHeapIsAligned(blksize));
        mheap_assert(blksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert(blksize <= MHEAP_BLKSIZE_MAX);
        const struct mheapblkhdr *p_nextblkhdr =
                (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
        mheap_assert(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
        mheap_assert(p_nextblkhdr->prev == blksize);

        if (blksize >= req_size) {
            return p_blk;
        } else if (blksize > largest_free_blksize) {
            p_largest_free_blk = p_blk;
            largest_free_blksize = blksize;
        }
    }

    return p_largest_free_blk;
}


/* Find a free block with at least the specified size (including overhead)
 *
 * Returns: on success: pointer to the found block
 *          on failure (no free blocks): NULL
 */
static struct mheapfreeblk *MHeapFindFreeBlock(
        const struct mheapstate *heap_state,
        tMHeapBlockSize req_size)
{
    struct mheapfreeblk *p_freeblk = MHeapFindFreeOrLargestBlock(heap_state,
                                                                 req_size);
    if (p_freeblk
            && (MHeapBlkToBlkHdrPtr(p_freeblk)->head & MHEAPBLK_SIZE_MASK)
                    >= req_size) {
        // Found a free block large enough
        return p_freeblk;
    }

    // Not found
    return NULL;
}


/* Walk a specified block range, calling the block post-movement callback
 * for every allocated block found
 *
 * The block range must belong to a single segment
 */
static void MHeapCallBlkProcInRange(
        struct mheapblkhdr *p_startblkhdr,  // -> starting block's header
        struct mheapblkhdr *p_endblkhdr,    // -> ending block's header
        tMHeapBlkPostMoveProc *proc)        // -> block post-movement procedure
{
    assert(p_startblkhdr != NULL);
    assert(p_endblkhdr != NULL);

    const tMHeapBlockSize *p_blkhead = &p_startblkhdr->head;
    const tMHeapBlockSize * const p_endblkhead = &p_endblkhdr->head;
    while (p_blkhead != p_endblkhead) {
        mheap_assert_par(p_blkhead < p_endblkhead);

        tMHeapBlockSize blksize = *p_blkhead & MHEAPBLK_SIZE_MASK;
        bool cinuse = *p_blkhead & MHEAPBLK_FLAG_CINUSE;

        mheap_assert_par(MHeapIsAligned(blksize));
        mheap_assert_par(blksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);

        const tMHeapBlockSize *p_nextblkhead =
                (tMHeapBlockSize *)((char *)p_blkhead + blksize);
        mheap_assert_par((*p_nextblkhead & MHEAPBLK_FLAG_PINUSE) == cinuse);
#if MHEAP_USE_DOUBLE_LINKS
        const struct mheapblkhdr *p_nextblkhdr =
                MHeapBlkHeadToBlkHdrPtr(p_nextblkhead);
        mheap_assert_par(p_nextblkhdr->prev == blksize);
#endif
        if (EXPECT_TRUE(cinuse)) {
            proc(MHeapBlkHeadToBlkPtr(p_blkhead));
        }

        p_blkhead = p_nextblkhead;
    }
}


/* Defragment a segment without calling the block post-movement callback
 *
 * Returns: true = some blocks have been moved
 *              range of moved blocks returned in `*pp_firstmovedblkhdr`
 *              and `*pp_endmovedblkhdr`
 *          false = no blocks have been moved
 *              `*pp_firstmovedblkhdr` and `*pp_endmovedblkhdr` unchanged
 */
static bool MHeapDefragSegDeferCallback(
        struct mheapstate *heap_state,
        struct mheapsegment * restrict p_seg,
        struct mheapblkhdr ** restrict pp_firstmovedblkhdr, // -> out: -> first moved block
        struct mheapblkhdr ** restrict pp_endmovedblkhdr)   // -> out: -> end of the moved blocks area
{
    tMHeapBlockSize *p_blkhead = &MHeapGetSegFirstBlkHdr(p_seg)->head;
    tMHeapBlockSize blksize = 0;

    /*
     * Find the first unallocated block in the segment
     */
    do {
        p_blkhead = (tMHeapBlockSize *)((char *)p_blkhead + blksize);
        blksize = *p_blkhead & MHEAPBLK_SIZE_MASK;

        if (blksize != 0) {
            mheap_assert(MHeapIsAligned(blksize));
            mheap_assert(blksize >= MHEAP_BLKSIZE_MIN);
            mheap_assert(blksize <= MHEAP_BLKSIZE_MAX);
        }
        mheap_assert(*p_blkhead & MHEAPBLK_FLAG_PINUSE);
    } while ((*p_blkhead & MHEAPBLK_FLAG_CINUSE) && blksize != 0);

    if (blksize == 0)
        return false;  // no free blocks, nothing to defragment

    /*
     * Make allocated blocks contiguous; destroy all free blocks
     */
    void *p_trackedblkhead =
            heap_state->p_tracked_block ?
                    &MHeapBlkToBlkHdrPtr(heap_state->p_tracked_block)->head :
                    NULL;
    struct mheapblkhdr *p_firstmovedblkhdr =
            MHeapBlkHeadToBlkHdrPtr(p_blkhead);
    tMHeapBlockSize *p_destblkhead = p_blkhead;
    tMHeapBlockSize move_offset = 0;
    do {
        move_offset += blksize;
        assert2(move_offset >= blksize, "Overflow!");

        /*
         * Unlink the free block about to be destroyed
         * (only if it is large enough to be actually linked)
         */
        if (blksize >= MHEAP_FREEBLKSIZE_MIN)
            MHeapRemoveFreeBlockFromList(MHeapBlkHeadToBlkPtr(p_blkhead));

        /*
         * Scan adjacent allocated blocks
         */
        p_blkhead = (tMHeapBlockSize *)((char *)p_blkhead + blksize);
        mheap_assert(!(*p_blkhead & MHEAPBLK_FLAG_PINUSE));
        mheap_assert(*p_blkhead & MHEAPBLK_FLAG_CINUSE);

        tMHeapBlockSize *p_srcblkhead = p_blkhead;
        assert((uintmax_t)((char *)p_srcblkhead - (char *)p_destblkhead)
                   == move_offset);

        do {
            if (p_blkhead == p_trackedblkhead) {
                // Hit the tracked block -- adjust its address
                heap_state->p_tracked_block =
                        (char *)MHeapBlkHeadToBlkPtr(p_blkhead) - move_offset;
                p_trackedblkhead = NULL;
            }

            blksize = *p_blkhead & MHEAPBLK_SIZE_MASK;
            if (blksize == 0 || !(*p_blkhead & MHEAPBLK_FLAG_CINUSE))
                break;

            mheap_assert(MHeapIsAligned(blksize));
            mheap_assert(blksize >= MHEAP_BLKSIZE_MIN);
            mheap_assert(blksize <= MHEAP_BLKSIZE_MAX);

            p_blkhead = (tMHeapBlockSize *)((char *)p_blkhead + blksize);
            mheap_assert(*p_blkhead & MHEAPBLK_FLAG_PINUSE);
        } while (true);  // exit condition inside the loop

        /*
         * Move the blocks all at once
         */
        assert(((char *)p_blkhead - (char *)p_srcblkhead) >= 0);
        assert((uintmax_t)((char *)p_blkhead - (char *)p_srcblkhead)
                <= MHEAP_BLKSIZE_MAX);

        tMHeapBlockSize move_size =
                (tMHeapBlockSize)((char *)p_blkhead - (char *)p_srcblkhead);
        memmove(p_destblkhead, p_srcblkhead, move_size);
        *p_destblkhead |= MHEAPBLK_FLAG_PINUSE;

        p_destblkhead =
                (tMHeapBlockSize *)((char *)p_destblkhead + move_size);
    } while (blksize != 0);

    /*
     * Turn the remaining space into a single free block
     * NB: if we got here then there must have been some free space
     */
    assert((*p_blkhead & MHEAPBLK_SIZE_MASK) == 0);
    assert(*p_blkhead & MHEAPBLK_FLAG_CINUSE);
    mheap_assert((uintmax_t)((char *)p_blkhead - (char *)p_destblkhead)
                     == p_seg->total_free);

    p_seg->n_freeblks = 0;
    MHeapMakeFreeBlock(heap_state,
                       p_seg,
                       MHeapBlkHeadToBlkPtr(p_destblkhead),
                       (tMHeapBlockSize)((char *)p_blkhead
                               - (char *)p_destblkhead));

    /*
     * Return the range of moved blocks
     */
    *pp_firstmovedblkhdr = p_firstmovedblkhdr;
    *pp_endmovedblkhdr = MHeapBlkHeadToBlkHdrPtr(p_destblkhead);
    return true;
}


/* Defragment a segment, then call the block post-movement callback
 */
static void MHeapDefragSeg(
        struct mheapstate *heap_state,
        struct mheapsegment * restrict p_seg)
{
    assert(heap_state->blk_post_move_proc != NULL);

    struct mheapblkhdr *p_firstmovedblkhdr, *p_endmovedblkhdr;
    if (MHeapDefragSegDeferCallback(heap_state,
                                    p_seg,
                                    &p_firstmovedblkhdr,
                                    &p_endmovedblkhdr)) {
        MHeapCallBlkProcInRange(p_firstmovedblkhdr,
                                p_endmovedblkhdr,
                                heap_state->blk_post_move_proc);
    }
}


/* Find the segment list pointer to the current segment
 *
 * Returns: address of the pointer to the current segment
 */
static struct mheapsegment **MHeapFindPrevSegPtr(
        struct mheapstate *heap_state,
        struct mheapsegment *p_seg)
{
    struct mheapsegment **pp_seg = &heap_state->seglist;
    while (*pp_seg != p_seg) {
        mheap_assert(*pp_seg != NULL);
        pp_seg = &(*pp_seg)->next;
    }

    return pp_seg;
}


/* Deallocate a segment if it is empty
 *
 * Returns: true = success, segment deallocated
 *          false = segment not deallocated
 */
static bool MHeapTryFreeSegment(
        struct mheapstate *heap_state,
        struct mheapsegment *p_seg,
        struct mheapsegment **pp_seg)   // -> list pointer to this segment; NULL if not known
{
    assert(p_seg != NULL);

    if (p_seg->n_usedblks > 0                   /* segment is in use */
            || p_seg->base_offset != 0          /* someone else may be using this segment */
            || !heap_state->seg_realloc_proc)   /* no procedure to free the segment */
        return false;

    mheap_assert(p_seg->n_freeblks == 1);

    if (!pp_seg) pp_seg = MHeapFindPrevSegPtr(heap_state, p_seg);
    assert(*pp_seg == p_seg);

    struct mheapfreeblk *p_freeblk = MHeapGetSegFirstBlk(p_seg);
    const tMHeapBlockSize *p_freeblkhead =
            &MHeapBlkToBlkHdrPtr(p_freeblk)->head;
    mheap_assert(!(*p_freeblkhead & MHEAPBLK_FLAG_CINUSE));
    mheap_assert(*p_freeblkhead & MHEAPBLK_FLAG_PINUSE);
    tMHeapBlockSize blksize = *p_freeblkhead & MHEAPBLK_SIZE_MASK;
    mheap_assert(MHeapIsAligned(blksize));
    mheap_assert(blksize >= MHEAP_FREEBLKSIZE_MIN);
    mheap_assert(blksize <= MHEAP_BLKSIZE_MAX);
    const struct mheapblkhdr *p_nextblkhdr =
            MHeapBlkToBlkHdrPtr((char *)p_freeblk + blksize);
    mheap_assert(p_nextblkhdr->prev == blksize);
    mheap_assert(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE);
    mheap_assert(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
    mheap_assert((p_nextblkhdr->head & MHEAPBLK_SIZE_MASK) == 0);

    MHeapRemoveFreeBlockFromList(p_freeblk);

    *pp_seg = p_seg->next;

    assert(heap_state->n_segments > 0);
    heap_state->n_segments--;

    size_t segsize = p_seg->alloc_size;
    (void)heap_state->seg_realloc_proc(p_seg, &segsize, 0);

    return true;
}


/* Auxiliary: Change the size of a segment
 *
 * Returns: true = OK, false = realloc/resize callback failed
 */
static bool MHeapChangeSegmentSize(
        struct mheapstate *heap_state,
        // -> in: pointer to the segment to be resized/reallocated
        //    out: new segment pointer
        struct mheapsegment ** restrict const pp_seg,
        // -> final free block in the segment
        struct mheapfreeblk *p_finalfreeblk,
        // preferred new segment size (0 = do not use)
        size_t new_segalloc_pref,
        // minimum new segment size
        size_t new_segalloc_min,
        // true = reallocate, false = resize
        bool realloc_segment,
        // -> header of the first block moved due to pre-defragmentation
        // NULL if the segment has not been pre-defragmented
        struct mheapblkhdr *p_firstmovedblkhdr,
        // -> end of the area of blocks moved due to pre-defragmentation
        // N/A if the segment has not been pre-defragmented
        struct mheapblkhdr *p_endmovedblkhdr)
{
    struct mheapsegment *p_seg = *pp_seg;

    mheap_assert_par(MHeapGetSegFinalFreeBlock(p_seg) == p_finalfreeblk);
    mheap_assert(p_seg->base_offset <= (SIZE_MAX - MHEAP_SEG_TOTAL_SIZE_MIN));
    assert(new_segalloc_min >= (p_seg->base_offset + MHEAP_SEG_TOTAL_SIZE_MIN));

    const tMHeapBlockSize o_finalfreeblk = (tMHeapBlockSize)((char *)(
            p_finalfreeblk ? p_finalfreeblk : MHeapGetSegEnd(p_seg))
            - (char *)MHeapGetSegFirstBlk(p_seg));
    tMHeapBlockSize finalfreeblksize =
            p_finalfreeblk ?
                    MHeapBlkToBlkHdrPtr(p_finalfreeblk)->head
                            & MHEAPBLK_SIZE_MASK :
                    0;
    assert(p_seg->size > finalfreeblksize);

    if (p_finalfreeblk) MHeapKillFreeBlock(p_seg, p_finalfreeblk);

    const size_t segbaseoffset = p_seg->base_offset;
    void *segbase = (char *)p_seg - segbaseoffset;
    size_t segallocsize = p_seg->alloc_size;
    struct mheapsegment **p_seglink = NULL;
    ptrdiff_t trackedblkoffset = -1;
    bool segaddr_changed = false;
    bool resize_status = false;

    if (realloc_segment) {
        assert(heap_state->seg_realloc_proc != NULL);
        assert(segbaseoffset == 0);
        /*
         * To simplify things, we allow a segment to be reallocated
         * only if it is defragmented.  This means all of the segment's
         * free space, if any, is in a single block at the end,
         * and we have just unlinked this block.
         */
        assert(p_seg->n_freeblks == 0);
        assert(p_seg->total_free == finalfreeblksize);

        /*
         * If a block is currently being tracked and it is in this segment,
         * remember its offset from the first block in the segment, so we can
         * restore the pointer to the block after the segment is moved.
         */

        if (heap_state->p_tracked_block
                && MHeapIsBlockInSegment(heap_state,
                                         p_seg,
                                         heap_state->p_tracked_block)) {
            trackedblkoffset = (char *)heap_state->p_tracked_block
                    - (char *)MHeapGetSegFirstBlk(p_seg);
        }

        // Find the pointer to this segment in the segment list
        p_seglink = MHeapFindPrevSegPtr(heap_state, p_seg);

        /*
         * Do the reallocation
         */

        void *new_segbase = NULL;
        // First try the preferred new size
        if (new_segalloc_pref > new_segalloc_min) {
            new_segbase = heap_state->seg_realloc_proc(segbase,
                                                       &segallocsize,
                                                       new_segalloc_pref);
        }
        // If that fails, try the minimum new size
        if (!new_segbase) {
            assert(segallocsize == p_seg->alloc_size);
            new_segbase = heap_state->seg_realloc_proc(segbase,
                                                       &segallocsize,
                                                       new_segalloc_min);
        }

        if (new_segbase) {
            resize_status = true;
            /*
             * Check if the segment's address has changed.
             * To avoid undefined behaviour due to the fact that `segbase`
             * may be no longer valid, we compare the pointers byte-by-byte.
             * The static assertion below actually tests if the pointer types
             * are compatible (which means they have the same representation);
             * if they're not, it will cause a diagnostic.
             */
            static_assert1(sizeof(segbase > new_segbase));
            segaddr_changed =
                    (memcmp(&segbase, &new_segbase, sizeof segbase) != 0);
            segbase = new_segbase;
        } else {
            assert(segallocsize == p_seg->alloc_size);
        }
    } else {
        assert(heap_state->seg_resize_proc != NULL);

        /*
         * Do the resizing
         */

        size_t new_segallocsize = 0;
        // First try the preferred new size
        if (new_segalloc_pref > new_segalloc_min) {
            new_segallocsize = heap_state->seg_resize_proc(segbase,
                                                           segallocsize,
                                                           new_segalloc_pref);
        }
        // If that fails, try the minimum new size
        if (!new_segallocsize) {
            new_segallocsize = heap_state->seg_resize_proc(segbase,
                                                           segallocsize,
                                                           new_segalloc_min);
        }

        if (new_segallocsize) {
            resize_status = true;
            segallocsize = new_segallocsize;
            if (segbase == heap_state) {
                // this segment's space also contains the heap state block
                heap_state->alloc_size = new_segallocsize;
            }
        }
    }

    assert(segallocsize >= (segbaseoffset + MHEAP_SEG_TOTAL_SIZE_MIN));

    p_seg = (struct mheapsegment *)((char *)segbase + segbaseoffset);
    if (segaddr_changed) {
        assert(p_seglink != NULL);
        *p_seglink = p_seg;
        if (trackedblkoffset >= 0) {
            heap_state->p_tracked_block =
                    (char *)MHeapGetSegFirstBlk(p_seg) + trackedblkoffset;
        }
    }
    *pp_seg = p_seg;

    p_seg->alloc_size = segallocsize;
    // align, in the unlikely case we get an unaligned value
    size_t new_segsize =
            MHeapAlignDown(segallocsize - segbaseoffset
                               - MHEAP_SEG_FIRST_BLK_OFFSET);
    if (new_segsize > MHEAP_SEG_SIZE_MAX) {
        new_segsize = MHEAP_SEG_SIZE_MAX;
    }

    size_t old_segsize = p_seg->size;
    assert(p_seg->size > finalfreeblksize);
    assert3(CRITICAL, new_segsize >= (old_segsize - finalfreeblksize), NULL);

    p_seg->size = (tMHeapBlockSize)new_segsize;
    p_seg->total_free += (tMHeapBlockSize)(new_segsize - old_segsize);
    assert(p_seg->size >= p_seg->total_free);
    assert(p_seg->total_free >= MHEAP_FREEBLKSIZE_MIN);

    /*
     * (Re-)create the final free block if there is enough space for it
     */

    p_finalfreeblk = (struct mheapfreeblk *)((char *)MHeapGetSegFirstBlk(p_seg)
            + o_finalfreeblk);

    void *p_endblk = MHeapGetSegEnd(p_seg);
    ptrdiff_t new_finalfreeblksize = (char *)p_endblk - (char *)p_finalfreeblk;
    assert(new_finalfreeblksize >= 0);

    if (new_finalfreeblksize < (int)MHEAP_BLKSIZE_MIN) {
        /*
         * Too little space left for a free block.
         * Reduce the usable segment size to leave the extra bytes out.
         */
        p_seg->size -= (tMHeapBlockSize)new_finalfreeblksize;
        if (p_seg->size < MHEAP_SEG_SIZE_MIN) {
            /*
             * This is a special (and quite unlikely, but possible) case.
             * To prevent shrinking the segment too much, we have to enlarge
             * the last allocated block.
             */
            char *p_blk = MHeapGetSegFirstBlk(p_seg);
            do {
                tMHeapBlockSize blksize =
                        MHeapBlkToBlkHdrPtr(p_blk)->head & MHEAPBLK_SIZE_MASK;
                mheap_assert(MHeapIsAligned(blksize));
                mheap_assert(blksize >= MHEAP_BLKSIZE_MIN);
                mheap_assert(blksize <= MHEAP_BLKSIZE_MAX);

                void *p_nextblk = p_blk + blksize;
                if (p_nextblk == p_finalfreeblk)
                    break;

                p_blk = p_nextblk;
            } while (true);  // exit condition inside the loop
            // Found the last allocated block
            mheap_assert(MHeapBlkToBlkHdrPtr(p_blk)->head
                             & MHEAPBLK_FLAG_CINUSE);
            assert(MHeapIsAligned((tMHeapBlockSize)new_finalfreeblksize));
            MHeapBlkToBlkHdrPtr(p_blk)->head +=
                    (tMHeapBlockSize)new_finalfreeblksize;
#if MHEAP_USE_DOUBLE_LINKS
            MHeapBlkToBlkHdrPtr(p_finalfreeblk)->prev +=
                    (tMHeapBlockSize)new_finalfreeblksize;
#endif
            p_seg->size += (tMHeapBlockSize)new_finalfreeblksize;
            new_finalfreeblksize = 0;
        }
        p_seg->total_free -= (tMHeapBlockSize)new_finalfreeblksize;
        p_endblk = (char *)p_endblk - new_finalfreeblksize;
        p_finalfreeblk = p_endblk;
        new_finalfreeblksize = 0;
    }

    assert(p_seg->size >= MHEAP_SEG_SIZE_MIN);

    MHeapBlkToBlkHdrPtr(p_endblk)->head = MHEAPBLK_FLAG_CINUSE;  // end-of-segment sentinel (size == 0)
    if (new_finalfreeblksize > 0) {
        // OK, can re-create the final free block
        assert((uintmax_t)new_finalfreeblksize >= MHEAP_BLKSIZE_MIN);
        assert((uintmax_t)new_finalfreeblksize <= MHEAP_BLKSIZE_MAX);

        MHeapMakeFreeBlock(heap_state,
                           p_seg,
                           p_finalfreeblk,
                           (tMHeapBlockSize)new_finalfreeblksize);
    } else {
        assert(p_finalfreeblk == p_endblk);
        MHeapBlkToBlkHdrPtr(p_endblk)->head |= MHEAPBLK_FLAG_PINUSE;
    }

    struct mheapblkhdr *p_finalfreeblkhdr = MHeapBlkToBlkHdrPtr(p_finalfreeblk);
    assert(p_finalfreeblkhdr->head & MHEAPBLK_FLAG_PINUSE);
#if MHEAP_USE_DOUBLE_LINKS
    {
        size_t blksize = p_finalfreeblkhdr->prev;
        mheap_assert_par(MHeapIsAligned(blksize));
        mheap_assert_par(blksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);

        const tMHeapBlockSize *p_prevblkhead =
                (tMHeapBlockSize *)((char *)&p_finalfreeblkhdr->head
                        - blksize);
        mheap_assert_par(*p_prevblkhead & MHEAPBLK_FLAG_CINUSE);
        mheap_assert_par((*p_prevblkhead & MHEAPBLK_SIZE_MASK) == blksize);
    }
#endif

    if (segaddr_changed) {
        // must call the block post-movement callback for every allocated block
        p_firstmovedblkhdr = MHeapGetSegFirstBlkHdr(p_seg);
        p_endmovedblkhdr = p_finalfreeblkhdr;
    }

    /*
     * Allocated blocks may have been moved due to defragmentation
     * or reallocation; if either has happened, call the block post-movement
     * callbacks
     */
    if (p_firstmovedblkhdr)
            MHeapCallBlkProcInRange(p_firstmovedblkhdr,
                                    p_endmovedblkhdr,
                                    heap_state->blk_post_move_proc);

    return resize_status;
}


/* Decrease the size of a segment as much as possible
 */
static void MHeapShrinkSegment(
        struct mheapstate *heap_state,
        struct mheapsegment *p_seg)
{
    assert(p_seg != NULL);

    if (p_seg->base_offset == MHEAPSEG_BASEOFFSET_EXTERN)
        return;  // cannot resize externally provided segments

    if (!heap_state->seg_resize_proc
            && !(heap_state->seg_realloc_proc && heap_state->blk_post_move_proc
                    && p_seg->base_offset == 0)) {
        // no callbacks to do what we need to do
        return;
    }

    struct mheapfreeblk *p_finalfreeblk = MHeapGetSegFinalFreeBlock(p_seg);

    /*
     * Defragment the segment if possible
     */

    struct mheapblkhdr *p_firstmovedblkhdr = NULL, *p_endmovedblkhdr = NULL;
    if (heap_state->blk_post_move_proc) {
        /*
         * To avoid needless defragmentation runs, defragment only if there is
         * more than one free block, or if there are any free blocks
         * and the last block in the segment is not one of them.
         */
        if (p_seg->n_freeblks > 1
                || (p_seg->n_freeblks > 0 && !p_finalfreeblk)) {
            // we'll call the callbacks later
            (void)MHeapDefragSegDeferCallback(heap_state,
                                              p_seg,
                                              &p_firstmovedblkhdr,
                                              &p_endmovedblkhdr);
            p_finalfreeblk = MHeapGetSegFinalFreeBlock(p_seg);
        }
    }

    if (!p_finalfreeblk) {
        // final block is not free (perhaps no free space in the segment)
        // cannot shrink
        return;
    }

    struct mheapblkhdr *p_finalfreeblkhdr = MHeapBlkToBlkHdrPtr(p_finalfreeblk);
    tMHeapBlockSize freed_size = p_finalfreeblkhdr->head & MHEAPBLK_SIZE_MASK;
    assert(freed_size <= p_seg->size);
    if (freed_size > p_seg->size - MHEAP_SEG_SIZE_MIN) {
        // prevent segment from getting too small
        freed_size = (tMHeapBlockSize)(p_seg->size - MHEAP_SEG_SIZE_MIN);
    }

    size_t segallocsize = p_seg->alloc_size;
    size_t new_segallocsize = segallocsize - freed_size;
    mheap_assert(new_segallocsize <= segallocsize);

    (void)MHeapChangeSegmentSize(heap_state,
                                 &p_seg,
                                 p_finalfreeblk,
                                 0,
                                 new_segallocsize,
                                 !heap_state->seg_resize_proc,
                                 p_firstmovedblkhdr,
                                 p_endmovedblkhdr);
}


/* Increase the size of a segment to satisfy an allocation request
 *
 * Returns: true = success, false = failure
 */
static bool MHeapGrowSegment(
        struct mheapstate *heap_state,
        struct mheapsegment *p_seg,
        tMHeapBlockSize req_size,               // requested allocation size, including overhead
        bool realloc_segment,                   // true = reallocate, false = resize
        bool defrag_before_grow)                // defragment the segment before increasing its size
{
    assert(p_seg != NULL);

    if (!heap_state->blk_post_move_proc) {
        // cannot defragment if no post-movement callback
        defrag_before_grow = false;
    }

    struct mheapfreeblk *p_finalfreeblk = MHeapGetSegFinalFreeBlock(p_seg);
    tMHeapBlockSize exist_free = 0;
    if (defrag_before_grow) {
        exist_free = p_seg->total_free;
    } else if (p_finalfreeblk) {
        exist_free =
                MHeapBlkToBlkHdrPtr(p_finalfreeblk)->head & MHEAPBLK_SIZE_MASK;
    }

    assert(p_seg->size > exist_free);

    if (exist_free >= req_size && exist_free >= MHEAP_FREEBLKSIZE_MIN) {
        /*
         * The request can be satisfied without actually changing
         * the segment size!
         */
        if (defrag_before_grow)
            MHeapDefragSeg(heap_state, p_seg);

        return true;
    }

    if (p_seg->base_offset == MHEAPSEG_BASEOFFSET_EXTERN) {
        /*
         * Cannot resize/reallocate externally allocated segments
         */
        return false;
    }

    if (realloc_segment && p_seg->base_offset != 0) {
        /*
         * Cannot reallocate the segment that holds the heap state, either
         */
        return false;
    }

    if (realloc_segment && !defrag_before_grow) {
        /*
         * Must defragment before reallocation (see MHeapChangeSegmentSize)
         */
        return false;
    }

    size_t old_segsize_inuse = p_seg->size + MHEAP_SEG_FIRST_BLK_OFFSET;
    assert2(old_segsize_inuse >= MHEAP_SEG_FIRST_BLK_OFFSET, "Overflow!");

    tMHeapBlockSize segsize_inc_min = req_size - exist_free;
    size_t new_segsize_inuse_min = old_segsize_inuse + segsize_inc_min;
    size_t new_segalloc_min = new_segsize_inuse_min + p_seg->base_offset;
    if (new_segsize_inuse_min < old_segsize_inuse
            || new_segsize_inuse_min > MHEAP_SEG_TOTAL_SIZE_MAX
            || new_segalloc_min < new_segsize_inuse_min)
        return false;  // segment would be too large

    assert(p_seg->alloc_size >= old_segsize_inuse);
    assert(p_seg->base_offset <= (p_seg->alloc_size - old_segsize_inuse));
    size_t new_segalloc_pref =
            p_seg->alloc_size + heap_state->pref_seg_size_inc;
    if (new_segalloc_pref < p_seg->alloc_size
            || new_segalloc_pref - p_seg->base_offset
                    > MHEAP_SEG_TOTAL_SIZE_MAX) {
        // preferred increment results in a too large segment
        new_segalloc_pref = p_seg->base_offset + MHEAP_SEG_TOTAL_SIZE_MAX;
        if (new_segalloc_pref < p_seg->base_offset) {
            // overflow
            new_segalloc_pref = 0;
        }
    }

    struct mheapblkhdr *p_firstmovedblkhdr = NULL, *p_endmovedblkhdr = NULL;

    if (defrag_before_grow) {
        /*
         * We want to defragment the segment only if necessary.
         * The segment is fragmented if there is more than one free block,
         * or if there are any free blocks and the last block in the segment
         * is not one of them.
         */
        if (p_seg->n_freeblks > 1
                || (p_seg->n_freeblks > 0 && !p_finalfreeblk)) {
            // we'll call the callbacks later
            (void)MHeapDefragSegDeferCallback(heap_state,
                                              p_seg,
                                              &p_firstmovedblkhdr,
                                              &p_endmovedblkhdr);
            p_finalfreeblk = MHeapGetSegFinalFreeBlock(p_seg);
        }
    }

    return MHeapChangeSegmentSize(heap_state,
                                  &p_seg,
                                  p_finalfreeblk,
                                  new_segalloc_pref,
                                  new_segalloc_min,
                                  realloc_segment,
                                  p_firstmovedblkhdr,
                                  p_endmovedblkhdr);
}


/* Set up a new segment
 *
 * Returns: pointer to the new segment descriptor
 */
static struct mheapsegment *MHeapSetUpNewSegment(
        struct mheapstate *heap_state,
        void *base,
        size_t base_offset,
        size_t alloc_size)
{
    assert(base != NULL);
    assert(base_offset < alloc_size);

    size_t segsize_inuse = MHeapAlignDown(alloc_size - base_offset);
    assert(segsize_inuse >= MHEAP_SEG_TOTAL_SIZE_MIN);
    size_t segsize = segsize_inuse - MHEAP_SEG_FIRST_BLK_OFFSET;
    if (segsize > MHEAP_SEG_SIZE_MAX) segsize = MHEAP_SEG_SIZE_MAX;

    struct mheapsegment * restrict p_seg =
            (struct mheapsegment *)((char *)base + base_offset);
    *p_seg = (struct mheapsegment) {
        .base_offset = base_offset,
        .alloc_size = alloc_size,
        .size = (tMHeapBlockSize)segsize,
    };

    tMHeapBlockSize freeblksize = (tMHeapBlockSize)segsize;
    struct mheapblkhdr *p_firstblkhdr = MHeapGetSegFirstBlkHdr(p_seg);
    struct mheapblkhdr *p_endblkhdr = MHeapGetSegEndBlkHdr(p_seg);
    ptrdiff_t seglen = (char *)p_endblkhdr - (char *)p_firstblkhdr;
    assert((uintmax_t)seglen == freeblksize);

    p_seg->total_free = freeblksize;
    p_seg->n_freeblks = 1;
    p_seg->n_usedblks = 0;

    p_firstblkhdr->prev = 0;  // important if MHEAP_USE_DOUBLE_LINKS is true
    p_firstblkhdr->head = freeblksize | MHEAPBLK_FLAG_PINUSE;
    p_endblkhdr->prev = freeblksize;
    p_endblkhdr->head = MHEAPBLK_FLAG_CINUSE;

    struct mheapfreeblk *p_freeblk = MHeapBlkHdrToBlkPtr(p_firstblkhdr);
    p_freeblk->seg = p_seg;
    MHeapAddFreeBlockToList(heap_state, p_freeblk, freeblksize);

    /*
     * A newly allocated segment is the most likely candidate for future
     * resizing, so we're putting it at the front of the segment list.
     */
    p_seg->next = heap_state->seglist;
    heap_state->seglist = p_seg;

    heap_state->n_segments++;
    assert(heap_state->n_segments > 0);

    return p_seg;
}


/* Allocate a new segment to satisfy an allocation request
 *
 * Returns: true = success, false = failure
 */
static bool MHeapAllocNewSegment(
        struct mheapstate *heap_state,
        tMHeapBlockSize req_size)       // requested allocation size, including overhead
{
    assert(heap_state->seg_realloc_proc != NULL);

    size_t segsize_min = MHeapAlignUp(req_size + MHEAP_SEG_FIRST_BLK_OFFSET);
    // the first condition below is true if the addition overflowed
    if (segsize_min < req_size || segsize_min > MHEAP_SEG_TOTAL_SIZE_MAX)
        return false;

    if (segsize_min < MHEAP_SEG_TOTAL_SIZE_MIN)
        segsize_min = MHEAP_SEG_TOTAL_SIZE_MIN;

    struct mheapsegment *p_new_seg = NULL;
    size_t new_segsize = 0;

    // First try the preferred minimum size
    if (heap_state->pref_min_seg_size > segsize_min) {
        p_new_seg =
                heap_state->seg_realloc_proc(
                        NULL,
                        &new_segsize,
                        MHeapAlignUp(heap_state->pref_min_seg_size));
    }
    // If that fails, try the actual minimum size
    if (!p_new_seg) {
        p_new_seg = heap_state->seg_realloc_proc(NULL,
                                                 &new_segsize,
                                                 segsize_min);
    }

    if (!p_new_seg)
        return false;  // definitely failed

    //TODO: check if this segment is adjacent to another one
    (void)MHeapSetUpNewSegment(heap_state, p_new_seg, 0, new_segsize);
    return true;
}


/*
 * Allocation strategies to attempt when the existing free blocks
 * cannot satisfy the request
 */
enum alloc_strategy {
    ALLOC_STRATEGY_DEFRAG,          // if a segment has enough free space, defragment it
    ALLOC_STRATEGY_SEG_NEW,         // try to allocate a new segment
    ALLOC_STRATEGY_SEG_RESIZE,      // try to resize an existing segment
    ALLOC_STRATEGY_SEG_REALLOC,     // try to reallocate an existing segment
    ALLOC_STRATEGY_Count_
};


/* Auxiliary: attempt an allocation strategy
 *
 * Returns: on success: pointer to the free block; on failure: NULL
 */
static struct mheapfreeblk *MHeapTryAllocStrategy(
        struct mheapstate *heap_state,
        tMHeapBlockSize req_size,       // requested allocation size, including overhead
        unsigned flags,                 // combination of MHEAP_POLICY_*
        enum alloc_strategy strategy)
{
    switch (strategy) {
        case ALLOC_STRATEGY_DEFRAG:
            // Try locating a segment with enough free fragmented space
            for (struct mheapsegment *p_seg = heap_state->seglist; p_seg;
                    p_seg = p_seg->next) {
                if (p_seg->total_free >= req_size
                        && p_seg->total_free >= MHEAP_FREEBLKSIZE_MIN
                        && p_seg->n_freeblks > 1) {
                    // Segment found, defragment it
                    MHeapDefragSeg(heap_state, p_seg);
                    // The allocation should now succeed
                    struct mheapfreeblk *p_freeblk =
                            MHeapFindFreeBlock(heap_state, req_size);
                    assert2(p_freeblk,
                            "Heap segment statistics appear to be incorrect");
                    return p_freeblk;
                }
            }
            break;

        case ALLOC_STRATEGY_SEG_NEW:
            if (heap_state->n_segments >= USHRT_MAX)
                break;  // the number of segments is limited

            if (MHeapAllocNewSegment(heap_state, req_size)) {
                return MHeapFindFreeBlock(heap_state, req_size);
            }
            break;

        case ALLOC_STRATEGY_SEG_RESIZE:
        {
            bool defrag_flag = (bool)(flags & MHEAP_POLICY_CONSERVE_MEMORY);
            //TODO: if MHEAP_POLICY_CONSERVE_MEMORY is set then start from segment with most free space
            for (struct mheapsegment *p_seg = heap_state->seglist; p_seg;
                    p_seg = p_seg->next) {
                if (MHeapGrowSegment(heap_state,
                                     p_seg,
                                     req_size,
                                     false,
                                     defrag_flag)) {
                    // looks like we succeeded
                    return MHeapFindFreeBlock(heap_state, req_size);
                }
            }
            break;
        }

        case ALLOC_STRATEGY_SEG_REALLOC:
            //TODO: if MHEAP_POLICY_CONSERVE_MEMORY is set then sort segments by free space
            for (struct mheapsegment *p_seg = heap_state->seglist; p_seg;
                    p_seg = p_seg->next) {
                if (MHeapGrowSegment(heap_state,
                                     p_seg,
                                     req_size,
                                     true,
                                     true)) {
                    // looks like we succeeded
                    return MHeapFindFreeBlock(heap_state, req_size);
                }
            }
            break;

        default:
            assert(Not_Implemented);
    }

    // Failure
    return NULL;
}


/* Try to obtain a free block with at least the requested size
 *
 * Returns: on success: pointer to the free block; on failure: NULL
 */
static struct mheapfreeblk *MHeapAllocGetFreeBlk(
        struct mheapstate *heap_state,
        tMHeapBlockSize req_size,       // requested allocation size, including overhead
        unsigned flags)                 // combination of MHEAP_POLICY_*
{
    struct mheapfreeblk *p_freeblk = MHeapFindFreeBlock(heap_state, req_size);
    if (p_freeblk)
        return p_freeblk;  // found a free block large enough

    /*
     * The heap needs to be reorganized and/or grow in size.
     */

    /*
     * Allocation strategy priorities.  Higher value means higher priority.
     * Negative values mean the strategy will not be attempted.
     */
    signed char alloc_strategy_priority[ALLOC_STRATEGY_Count_] = {
        [ALLOC_STRATEGY_DEFRAG]         = 3 * ALLOC_STRATEGY_Count_,
        [ALLOC_STRATEGY_SEG_NEW]        = 1 * ALLOC_STRATEGY_Count_,
        [ALLOC_STRATEGY_SEG_RESIZE]     = 4 * ALLOC_STRATEGY_Count_,
        [ALLOC_STRATEGY_SEG_REALLOC]    = 2 * ALLOC_STRATEGY_Count_,
    };

    if (flags & MHEAP_POLICY_CONSERVE_MEMORY)
        alloc_strategy_priority[ALLOC_STRATEGY_DEFRAG] =
            (ALLOC_STRATEGY_Count_ + 1) * ALLOC_STRATEGY_Count_;

    if (flags & MHEAP_POLICY_AVOID_SEG_REALLOC)
        alloc_strategy_priority[ALLOC_STRATEGY_SEG_NEW] =
            alloc_strategy_priority[ALLOC_STRATEGY_SEG_REALLOC] + 1;

    if ((flags & MHEAP_POLICY_NO_BLOCK_MOVEMENT)
            || !heap_state->blk_post_move_proc) {
        // cannot move blocks around
        alloc_strategy_priority[ALLOC_STRATEGY_DEFRAG] = -1;
        alloc_strategy_priority[ALLOC_STRATEGY_SEG_REALLOC] = -1;
    }

    if (!heap_state->seg_realloc_proc) {
        alloc_strategy_priority[ALLOC_STRATEGY_SEG_NEW] = -1;
        alloc_strategy_priority[ALLOC_STRATEGY_SEG_REALLOC] = -1;
    }

    if (!heap_state->seg_resize_proc)
        alloc_strategy_priority[ALLOC_STRATEGY_SEG_RESIZE] = -1;

    signed char alloc_strategy_pri_min = INT8_MAX, alloc_strategy_pri_max = INT8_MIN;
    for (unsigned i = 0; i < ARRAY_LEN(alloc_strategy_priority); i++) {
        if (alloc_strategy_priority[i] < alloc_strategy_pri_min)
            alloc_strategy_pri_min = alloc_strategy_priority[i];
        if (alloc_strategy_priority[i] > alloc_strategy_pri_max)
            alloc_strategy_pri_max = alloc_strategy_priority[i];
    }
    if (alloc_strategy_pri_min < 0) alloc_strategy_pri_min = 0;

    /*
     * Attempt the allocation strategies according to their priorities
     */

    for (signed char priority = alloc_strategy_pri_max;
            priority >= alloc_strategy_pri_min; priority--) {
        for (enum alloc_strategy strategy = (enum alloc_strategy)0;
                strategy < ARRAY_LEN(alloc_strategy_priority); strategy++) {
            if (alloc_strategy_priority[strategy] == priority) {
                p_freeblk = MHeapTryAllocStrategy(heap_state,
                                                  req_size,
                                                  flags,
                                                  strategy);
                if (p_freeblk) return p_freeblk;
            }
        }
    }

    // All strategies have failed
    return NULL;
}


/* Allocate a memory block on a custom heap
 *
 * Returns: on success: pointer to the allocated block; on failure: NULL
 */
void *MHeapAlloc(
        tMHeapHandle heap_handle,       // heap handle
        size_t size)                    // requested allocation size
{
    return MHeapAllocEx(heap_handle, size, heap_handle->policy_flags);
}


/* Allocate a memory block on a custom heap, with flags
 *
 * Returns: on success: pointer to the allocated block; on failure: NULL
 */
void *MHeapAllocEx(
        tMHeapHandle heap_handle,       // heap handle
        size_t size,                    // requested allocation size
        unsigned flags)                 // combination of MHEAP_POLICY_*
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    if (size > MHEAP_ALLOC_MAX) return NULL;  // excessively large requests always fail

    tMHeapBlockSize req_size = (tMHeapBlockSize)
                               (MHeapAlignUp(size + MHEAP_ALLOC_OVERHEAD));
    assert2(req_size >= size, "Overflow!");

    struct mheapfreeblk *p_freeblk = MHeapAllocGetFreeBlk(heap_handle,
                                                          req_size,
                                                          flags);

    if (EXPECT_TRUE(p_freeblk != NULL)) {
        void *p_blk = MHeapAllocFreeBlock(heap_handle,
                                          p_freeblk,
                                          req_size,
                                          flags);

        MHeapAssertValidPtr(heap_handle, p_blk);
        return p_blk;
   }

   return NULL;
}


/* Try to resize a memory block without moving it
 *
 * Returns: on success: 0
 *          on failure: number of free bytes missing after the block
 *                      to complete the request
 */
static tMHeapBlockSize MHeapTryResizeBlock(
        struct mheapstate *heap_state,
        struct mheapsegment ** restrict pp_seg, // -> I/O: segment pointer, NULL if not known
        void *p_blk,                            // -> block
        tMHeapBlockSize req_size)               // requested new size, including overhead
{
    assert(pp_seg != NULL);
    assert(MHeapIsAligned(req_size));
    assert(req_size >= MHEAP_BLKSIZE_MIN);
    assert(req_size <= MHEAP_BLKSIZE_MAX);

    struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    mheap_assert_par(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE);

    const tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    mheap_assert_par(MHeapIsAligned(blksize));
    mheap_assert_par(blksize >= MHEAP_BLKSIZE_MIN);
    mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);

    if (EXPECT_FALSE(blksize == req_size))
        return 0;  // nothing to do!

    struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    mheap_assert_par(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE);
#if MHEAP_USE_DOUBLE_LINKS
    mheap_assert_par(p_nextblkhdr->prev == blksize);
#endif

    struct mheapblkhdr *p_freeblkhdr = NULL;
    tMHeapBlockSize freeblksize = 0;
    if (!(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE)) {
        // The next block is free
        p_freeblkhdr = p_nextblkhdr;
        freeblksize = p_freeblkhdr->head & MHEAPBLK_SIZE_MASK;
        mheap_assert_par(MHeapIsAligned(freeblksize));
        mheap_assert_par(freeblksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(freeblksize <= MHEAP_BLKSIZE_MAX);

        if (freeblksize >= MHEAP_FREEBLKSIZE_MIN) {
            // remember the segment pointer while we've got it
            const struct mheapfreeblk *p_freeblk =
                    MHeapBlkHdrToBlkPtr(p_freeblkhdr);
            struct mheapsegment *p_seg = p_freeblk->seg;
            mheap_assert_par(MHEAP_IS_PTR_IN_SEGMENT(p_seg, p_freeblk));
            if (*pp_seg) mheap_assert_par(*pp_seg == p_seg);
            *pp_seg = p_seg;
        }

        p_nextblkhdr =
                (struct mheapblkhdr *)((char *)p_freeblkhdr + freeblksize);
        mheap_assert_par(!(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE));
        mheap_assert_par(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE);
        mheap_assert_par(p_nextblkhdr->prev == freeblksize);
    }

    tMHeapBlockSize avail_size = blksize + freeblksize;
    assert2(avail_size >= blksize, "Overflow!");

    if (req_size > avail_size)
        return req_size - avail_size;  // cannot resize

    // The block can be resized.
    // First, we need to know which segment the block belongs to.
    if (!*pp_seg) *pp_seg = MHeapGetBlockSegment(heap_state, p_blk);
    mheap_assert_par(MHEAP_IS_PTR_IN_SEGMENT(*pp_seg, p_blk));

    // If the next block is free, remove it.
    if (p_freeblkhdr)
        MHeapKillFreeBlock(*pp_seg, MHeapBlkHdrToBlkPtr(p_freeblkhdr));

    tMHeapBlockSize rem_size = avail_size - req_size;
    if (rem_size < MHEAP_BLKSIZE_MIN) {
        // Not enough space left for a free block; allocate the whole space
        req_size = avail_size;
        rem_size = 0;
    }

    // Update the block size
    p_blkhdr->head = req_size | MHEAPBLK_FLAG_CINUSE
            | (p_blkhdr->head & MHEAPBLK_FLAG_PINUSE);
    if (rem_size > 0) {
        // (Re)create a free block in the remaining space
        p_freeblkhdr = (struct mheapblkhdr *)((char *)p_blkhdr + req_size);
        MHeapMakeFreeBlock(heap_state,
                           *pp_seg,
                           MHeapBlkHdrToBlkPtr(p_freeblkhdr),
                           rem_size);
        p_nextblkhdr = p_freeblkhdr;
    } else {
        p_nextblkhdr->head |= MHEAPBLK_FLAG_PINUSE;
    }
#if MHEAP_USE_DOUBLE_LINKS
    p_nextblkhdr->prev = req_size;
#endif

    (*pp_seg)->total_free += blksize;
    assert2((*pp_seg)->total_free >= blksize, "Overflow!");
    assert((*pp_seg)->total_free >= req_size);
    (*pp_seg)->total_free -= req_size;

    return 0;
}


/* Try to resize a memory block's containing segment so the block
 * can be resized without moving it, if possible
 *
 * The caller is expected to have tried MHeapTryResizeBlock() first.
 *
 * Returns: true = success, false = failure
 */
static bool MHeapTryResizeBlockWithSeg(
        struct mheapstate *heap_state,
        struct mheapsegment ** restrict pp_seg, // -> I/O: segment pointer, NULL if not known
        void *p_blk,                            // -> block
        tMHeapBlockSize req_size)               // requested new size, including overhead
{
    assert(pp_seg != NULL);

    if (!heap_state->seg_resize_proc)
        return false;  // no segment resize procedure

    struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    if (!(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE)) {
        // the next block is free, check the following block
        struct mheapblkhdr *p_freeblkhdr = p_nextblkhdr;
        tMHeapBlockSize freeblksize = p_freeblkhdr->head & MHEAPBLK_SIZE_MASK;

        p_nextblkhdr =
                (struct mheapblkhdr *)((char *)p_freeblkhdr + freeblksize);
    }

    if ((p_nextblkhdr->head & MHEAPBLK_SIZE_MASK) != 0)
        return false;  // the block is not the last one

    /*
     * OK, try to extend the segment
     */

    if (!*pp_seg) *pp_seg = MHeapGetBlockSegment(heap_state, p_blk);
    if (MHeapGrowSegment(heap_state, *pp_seg, req_size, false, false)) {
        // the resizing should now succeed
        tMHeapBlockSize req_fail =
                MHeapTryResizeBlock(heap_state, pp_seg, p_blk, req_size);
        assert(req_fail == 0);
        return true;
    }

    // Failed
    return false;
}


/* Resize a memory block on a custom heap (without moving the block)
 *
 * Returns: on success: pointer to the block (same as input); on failure: NULL
 */
void *MHeapResize(
        tMHeapHandle heap_handle,       // heap handle
        void *p_blk,                    // -> block to resize
        size_t size)                    // requested new block size
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    assert3(THOROUGH,
            MHeapIsValidPtr(heap_handle, p_blk),
            "Wrong pointer or heap corrupted");

    if (size > MHEAP_ALLOC_MAX) return NULL;  // excessively large requests always fail

    tMHeapBlockSize req_size = (tMHeapBlockSize)
                               (MHeapAlignUp(size + MHEAP_ALLOC_OVERHEAD));
    assert2(req_size >= size, "Overflow!");

    struct mheapsegment *p_seg = NULL;
    if (MHeapTryResizeBlock(heap_handle, &p_seg, p_blk, req_size) == 0) {
        MHeapAssertValidPtr(heap_handle, p_blk);
        return p_blk;
    }

    if (MHeapTryResizeBlockWithSeg(heap_handle, &p_seg, p_blk, req_size)) {
        MHeapAssertValidPtr(heap_handle, p_blk);
        return p_blk;
    }

    // Failed
    return NULL;
}


/* Reallocate a memory block on a custom heap
 *
 * Note: resizing a block to zero does not free the block
 *
 * Returns: on success: new pointer to the block; on failure: NULL
 */
void *MHeapRealloc(
        tMHeapHandle heap_handle,       // heap handle
        void *p_blk,                    // -> block to reallocate
        size_t size)                    // requested new block size
{
    return MHeapReallocEx(heap_handle, p_blk, size, heap_handle->policy_flags);
}


/* Reallocate a memory block on a custom heap, with flags
 *
 * Note: resizing a block to zero does not free the block
 *
 * Returns: on success: new pointer to the block; on failure: NULL
 */
void *MHeapReallocEx(
        tMHeapHandle heap_handle,       // heap handle
        void *p_blk,                    // -> block to reallocate
        size_t size,                    // requested new block size
        unsigned flags)                 // combination of MHEAP_POLICY_*
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    assert3(THOROUGH,
            MHeapIsValidPtr(heap_handle, p_blk),
            "Wrong pointer or heap corrupted");

    if (size > MHEAP_ALLOC_MAX) return NULL;  // excessively large requests always fail

    tMHeapBlockSize req_size = (tMHeapBlockSize)
                               (MHeapAlignUp(size + MHEAP_ALLOC_OVERHEAD));
    assert2(req_size >= size, "Overflow!");

    struct mheapsegment *p_seg = NULL;
    tMHeapBlockSize req_fail =
            MHeapTryResizeBlock(heap_handle, &p_seg, p_blk, req_size);
    if (req_fail == 0) {
        MHeapAssertValidPtr(heap_handle, p_blk);
        return p_blk;
    }

    /*
     * Not enough space after the block to resize it;
     * check if it might be possible to use a preceding free block
     */

    struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    const tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    tMHeapBlockSize freeblksize = 0;
    if (!(p_blkhdr->head & MHEAPBLK_FLAG_PINUSE)) {
        freeblksize = p_blkhdr->prev;
        mheap_assert_par(MHeapIsAligned(freeblksize));
        mheap_assert_par(freeblksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(freeblksize <= MHEAP_BLKSIZE_MAX);
    }

    if (freeblksize >= req_fail) {
        /*
         * OK, we'll have enough free space after the merger;
         * move the block down, then resize it
         */
        struct mheapblkhdr *p_freeblkhdr =
                (struct mheapblkhdr *)((char *)p_blkhdr - freeblksize);
        mheap_assert_par(!(p_freeblkhdr->head & MHEAPBLK_FLAG_CINUSE));
        mheap_assert_par(p_freeblkhdr->head & MHEAPBLK_FLAG_PINUSE);
        mheap_assert_par((p_freeblkhdr->head & MHEAPBLK_SIZE_MASK)
                             == freeblksize);

        if (!p_seg) p_seg = MHeapGetBlockSegment(heap_handle, p_blk);

        // Remove the free block
        MHeapKillFreeBlock(p_seg, MHeapBlkHdrToBlkPtr(p_freeblkhdr));

        struct mheapblkhdr *p_nextblkhdr =
                (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
        // assertions already handled in MHeapTryResizeBlock()
        tMHeapBlockSize nextblksize = 0;
        if (!(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE)) {
            MHeapKillFreeBlock(p_seg, MHeapBlkHdrToBlkPtr(p_nextblkhdr));
            nextblksize = p_nextblkhdr->head & MHEAPBLK_SIZE_MASK;
            p_nextblkhdr = (struct mheapblkhdr *)((char *)p_nextblkhdr
                    + nextblksize);
        }

        tMHeapBlockSize avail_size = blksize + freeblksize;
        assert2(avail_size >= blksize, "Overflow!");
        avail_size += nextblksize;
        assert2(avail_size >= nextblksize, "Overflow!");

        tMHeapBlockSize rem_size = avail_size - req_size;
        if (rem_size < MHEAP_BLKSIZE_MIN) {
            // Not enough space left for a free block; use the whole space
            req_size = avail_size;
            rem_size = 0;
        }

        // Move the block contents
        memmove(MHeapBlkHdrToBlkPtr(p_freeblkhdr),
                p_blk,
                (size_t)blksize - MHEAP_ALLOC_OVERHEAD);

        p_blkhdr = p_freeblkhdr;
        p_blk = MHeapBlkHdrToBlkPtr(p_blkhdr);

        // Update the block size
        p_blkhdr->head = req_size | MHEAPBLK_FLAG_CINUSE | MHEAPBLK_FLAG_PINUSE;
        if (rem_size > 0) {
            // Recreate a free block in the remaining space
            p_freeblkhdr = (struct mheapblkhdr *)((char *)p_blkhdr + req_size);
            MHeapMakeFreeBlock(heap_handle,
                               p_seg,
                               MHeapBlkHdrToBlkPtr(p_freeblkhdr),
                               rem_size);
        } else {
            p_nextblkhdr->head |= MHEAPBLK_FLAG_PINUSE;
#if MHEAP_USE_DOUBLE_LINKS
            p_nextblkhdr->prev = req_size;
#endif
        }

        tMHeapBlockSize size_inc = req_size - blksize;
        assert2(size_inc <= req_size, "Overflow!");
        assert(p_seg->total_free >= size_inc);
        p_seg->total_free -= size_inc;

        MHeapAssertValidPtr(heap_handle, p_blk);

        if (heap_handle->blk_post_move_proc)
            heap_handle->blk_post_move_proc(p_blk);

        return p_blk;
    }

    /*
     * Perhaps extending the segment would help
     */

    if (MHeapTryResizeBlockWithSeg(heap_handle, &p_seg, p_blk, req_size)) {
        MHeapAssertValidPtr(heap_handle, p_blk);
        return p_blk;
    }

    /*
     * None of the simple strategies above worked;
     * we need to allocate a whole new block and copy the contents
     */

    heap_handle->p_tracked_block = p_blk;

    p_blk = MHeapAllocEx(heap_handle, req_size - MHEAP_ALLOC_OVERHEAD, flags);
    if (p_blk) {
        // Success, move the block contents
        void *p_tracked_block = heap_handle->p_tracked_block;
        heap_handle->p_tracked_block = NULL;

        const tMHeapBlockSize blkobjsize = blksize - MHEAP_ALLOC_OVERHEAD;
#if HAVE_WELL_DEFINED_PTR_CMP
        assert2(((char *)p_tracked_block + blkobjsize) <= (char *)p_blk
                        || (char *)p_tracked_block
                                >= ((char *)p_blk + blkobjsize),
                "Overlap detected");
#endif
        memcpy(p_blk, p_tracked_block, blkobjsize);

        if (heap_handle->blk_post_move_proc)
            heap_handle->blk_post_move_proc(p_blk);

        // Free the old block
        MHeapFreeEx(heap_handle, p_tracked_block, flags);
    } else {
        heap_handle->p_tracked_block = NULL;
    }

    return p_blk;
}


/* Free an allocated memory block on a custom heap, with flags
 */
void MHeapFree(
        tMHeapHandle heap_handle,   // heap handle
        void *p_blk)                // -> block to free
{
    MHeapFreeEx(heap_handle, p_blk, heap_handle->policy_flags);
}


/* Free an allocated memory block on a custom heap
 */
void MHeapFreeEx(
        tMHeapHandle heap_handle,   // heap handle
        void *p_blk,                // -> block to free
        unsigned flags)             // combination of MHEAP_POLICY_*
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    assert3(THOROUGH,
            MHeapIsValidPtr(heap_handle, p_blk),
            "Wrong pointer or heap corrupted");

    struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    mheap_assert_par(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE);
    const tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    struct mheapsegment *p_seg = MHeapGetBlockSegment(heap_handle, p_blk);

    struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    mheap_assert_par(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE);
#if MHEAP_USE_DOUBLE_LINKS
    mheap_assert_par(p_nextblkhdr->prev == blksize);
#endif

    tMHeapBlockSize total_blksize = blksize;  // coalesced free block size

    if (!(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE)) {
        mheap_assert_par(p_nextblkhdr->prev == blksize);

        // next block is free, coalesce
        tMHeapBlockSize nextblksize = p_nextblkhdr->head & MHEAPBLK_SIZE_MASK;
        mheap_assert_par(MHeapIsAligned(nextblksize));
        mheap_assert_par(nextblksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(nextblksize <= MHEAP_BLKSIZE_MAX);

        MHeapKillFreeBlock(p_seg, MHeapBlkHdrToBlkPtr(p_nextblkhdr));

        p_nextblkhdr =
                (struct mheapblkhdr *)((char *)p_nextblkhdr + nextblksize);
#if MHEAP_USE_DOUBLE_LINKS
        mheap_assert_par(p_nextblkhdr->prev == nextblksize);
#endif
        total_blksize += nextblksize;
        assert2(total_blksize >= nextblksize, "Overflow!");
    }

    mheap_assert(p_nextblkhdr->head & MHEAPBLK_FLAG_CINUSE);

    if (!(p_blkhdr->head & MHEAPBLK_FLAG_PINUSE)) {
        // previous block is free, coalesce
        tMHeapBlockSize prevblksize = p_blkhdr->prev;
        mheap_assert_par(MHeapIsAligned(prevblksize));
        mheap_assert_par(prevblksize >= MHEAP_BLKSIZE_MIN);
        mheap_assert_par(prevblksize <= MHEAP_BLKSIZE_MAX);

        struct mheapblkhdr *p_prevblkhdr =
                (struct mheapblkhdr *)((char *)p_blkhdr - prevblksize);
        mheap_assert_par(!(p_prevblkhdr->head & MHEAPBLK_FLAG_CINUSE));
        mheap_assert_par(p_prevblkhdr->head & MHEAPBLK_FLAG_PINUSE);
        mheap_assert_par((p_prevblkhdr->head & MHEAPBLK_SIZE_MASK)
                             == prevblksize);

        MHeapKillFreeBlock(p_seg, MHeapBlkHdrToBlkPtr(p_prevblkhdr));

        p_blkhdr = p_prevblkhdr;
        total_blksize += prevblksize;
        assert2(total_blksize >= prevblksize, "Overflow!");
    }

    MHeapMakeFreeBlock(heap_handle,
                       p_seg,
                       MHeapBlkHdrToBlkPtr(p_blkhdr),
                       total_blksize);

    assert(p_seg->n_usedblks > 0);
    p_seg->n_usedblks--;
    p_seg->total_free += blksize;
    assert2(p_seg->total_free >= blksize, "Overflow!");

    if (!(flags & MHEAP_POLICY_KEEP_FREE_SEG))
        (void)MHeapTryFreeSegment(heap_handle, p_seg, NULL);

    MHeapAssertConsistency(heap_handle);
}


/* Get the size of an allocated block on a custom heap
 *
 * Returns: total size of the block (without overhead)
 *          (may be larger than the size specified in the allocation request);
 *          0 if `p_blk` is NULL
 */
tMHeapBlockSize MHeapGetSize(
        tMHeapHandle heap_handle,       // heap handle
        const void *p_blk)              // -> block
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    if (!p_blk) return 0;

    assert3(THOROUGH,
            MHeapIsValidPtr(heap_handle, p_blk),
            "Wrong pointer or heap corrupted");

    // check if the pointer seems to point to an allocated block
    struct mheapblkhdr *p_blkhdr = MHeapBlkToBlkHdrPtr(p_blk);
    mheap_assert_par(p_blkhdr->head & MHEAPBLK_FLAG_CINUSE);
    const tMHeapBlockSize blksize = p_blkhdr->head & MHEAPBLK_SIZE_MASK;
    mheap_assert_par(MHeapIsAligned(blksize));
    mheap_assert_par(blksize >= MHEAP_BLKSIZE_MIN);
    mheap_assert_par(blksize <= MHEAP_BLKSIZE_MAX);

    struct mheapblkhdr *p_nextblkhdr =
            (struct mheapblkhdr *)((char *)p_blkhdr + blksize);
    mheap_assert_par(p_nextblkhdr->head & MHEAPBLK_FLAG_PINUSE);
#if MHEAP_USE_DOUBLE_LINKS
    mheap_assert_par(p_nextblkhdr->prev == blksize);
#endif

    return blksize - MHEAP_ALLOC_OVERHEAD;
}


/* Get parameters of a custom heap
 */
void MHeapGetParameters(
        tMHeapHandle heap_handle,         // heap handle
        struct mheap_par * restrict par)  // -> out: heap parameters
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    par->seg_resize_proc    = heap_handle->seg_resize_proc;
    par->seg_realloc_proc   = heap_handle->seg_realloc_proc;
    par->blk_post_move_proc = heap_handle->blk_post_move_proc;
    par->pref_min_seg_size  = heap_handle->pref_min_seg_size;
    par->pref_seg_size_inc  = heap_handle->pref_seg_size_inc;
    par->policy_flags       = heap_handle->policy_flags;
}


/* Set parameters of a custom heap
 */
void MHeapSetParameters(
        tMHeapHandle heap_handle,               // heap handle
        const struct mheap_par * restrict par)  // -> heap parameters
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    heap_handle->seg_resize_proc    = par->seg_resize_proc;
    heap_handle->seg_realloc_proc   = par->seg_realloc_proc;
    heap_handle->blk_post_move_proc = par->blk_post_move_proc;
    heap_handle->pref_min_seg_size  = par->pref_min_seg_size;
    heap_handle->pref_seg_size_inc  = par->pref_seg_size_inc;
    heap_handle->policy_flags       = par->policy_flags;
}


/* Initialize a custom heap
 *
 * If `base` is NULL, the heap state is allocated using the segment
 * (re)allocation callback (which must be provided).   If `init_size` is
 * nonzero, at least that number of bytes will be allocated, and an initial
 * segment will be created after the heap state structure.
 *
 * If `base` is not NULL, it is assumed to point to a buffer `init_size` bytes
 * long.  The heap state, and an initial segment if the remaining space
 * suffices, will be both created in that buffer.  In that case, if no segment
 * (re)allocation callback is provided, the heap size is fixed.
 *
 * Returns: on success: heap handle
 *          on failure: MHEAP_INVALID_HANDLE
 */
tMHeapHandle MHeapInit(
        void *base,                             // -> base space; NULL = allocate own
        size_t init_size,                       // base space size or initial segment size
        const struct mheap_par * restrict par)  // -> heap parameters
{
    struct mheapstate *heap_state = NULL;

    const size_t min_state_seg_size =
            MHEAP_STATE_SIZE_ALIGNED + MHEAP_SEG_TOTAL_SIZE_MIN;
    size_t state_size = 0;

    if (base) {
        if (init_size < sizeof *heap_state)
            return MHEAP_INVALID_HANDLE;  // base space too small

        heap_state = base;
        state_size = init_size;
    } else {
        if (!par->seg_realloc_proc)
            return MHEAP_INVALID_HANDLE;  // no way to allocate the state

        size_t req_size = sizeof *heap_state;
        if (init_size > 0) {
            req_size = init_size;
            if (req_size < min_state_seg_size)
                req_size = min_state_seg_size;
        }

        heap_state = par->seg_realloc_proc(NULL, &state_size, req_size);
        if (!heap_state)
            return MHEAP_INVALID_HANDLE;  // could not allocate the state
    }

    assert(state_size >= sizeof *heap_state);

    *heap_state = (struct mheapstate) {
        .freeblkh = {
            .next = &heap_state->freeblkh,
            .prev = &heap_state->freeblkh,
        },
        .seglist = NULL,
        .p_tracked_block = NULL,
        .n_segments = 0,
    };
    if (!base) heap_state->alloc_size = state_size;
    MHeapSetParameters(heap_state, par);

    if (MHeapAlignDown(state_size) >= min_state_seg_size) {
        struct mheapsegment *initial_segment =
                MHeapSetUpNewSegment(heap_state,
                                     heap_state,
                                     MHEAP_STATE_SIZE_ALIGNED,
                                     state_size);
        if (base) initial_segment->base_offset = MHEAPSEG_BASEOFFSET_EXTERN;
    }

    MHeapAssertConsistency(heap_state);

    return heap_state;
}


/* Destroy a custom heap
 *
 * Deallocates all segments that have been allocated with the segment
 * (re)allocation callback.  If the heap state block has been allocated with
 * the callback, it is deallocated too.
 *
 * Returns: true = deallocation successful
 *          false = segment (re)allocation callback not available
 */
bool MHeapDestroy(tMHeapHandle heap_handle)
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    struct mheapstate *heap_state = heap_handle;
    tMHeapSegReallocProc *realloc_proc = heap_state->seg_realloc_proc;

    /*
     * Deallocate segments
     */

    for (struct mheapsegment *p_seg = heap_state->seglist, *p_next_seg;
            p_seg; p_seg = p_next_seg) {
        p_next_seg = p_seg->next;
        if (p_seg->base_offset == 0) {
            if (!realloc_proc) return false;

            size_t segsize = p_seg->alloc_size;
            (void)realloc_proc(p_seg, &segsize, 0);
        }
    }

    heap_state->freeblkh.next = NULL;
    heap_state->freeblkh.prev = NULL;
    heap_state->seglist = NULL;
    heap_state->n_segments = 0;

    /*
     * Deallocate the heap state block
     */

    if (heap_state->alloc_size != 0) {
        if (!realloc_proc) return false;

        size_t segsize = heap_state->alloc_size;
        (void)realloc_proc(heap_state, &segsize, 0);
    }

    return true;
}


/* Shrink all segments of a custom heap as much as possible
 */
void MHeapShrink(tMHeapHandle heap_handle)
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    struct mheapsegment **pp_seg = &heap_handle->seglist;
    while (*pp_seg) {
        /*
         * Remove the segment if it is not used.  If we succeed
         * then (*pp_seg) will be updated to point to the next segment.
         */
        if (!MHeapTryFreeSegment(heap_handle, *pp_seg, pp_seg)) {
            /*
             * Cannot remove the segment; try to shrink it, then move on
             * to the next segment.
             */
            MHeapShrinkSegment(heap_handle, *pp_seg);
            pp_seg = &(*pp_seg)->next;
        }
    }
}


/* Defragment all segments of a custom heap
 *
 * Returns: true = heap defragmented
 *          false = no block post-movement callback, cannot defragment
 */
bool MHeapDefrag(tMHeapHandle heap_handle)
{
    assert(heap_handle != MHEAP_INVALID_HANDLE);

    if (heap_handle->blk_post_move_proc) {
        for (struct mheapsegment *p_seg = heap_handle->seglist; p_seg;
                p_seg = p_seg->next) {
            MHeapDefragSeg(heap_handle, p_seg);
        }

        return true;
    } else {
        return false;
    }
}
