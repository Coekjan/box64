#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <setjmp.h>
#include <sys/mman.h>

#include "debug.h"
#include "box64context.h"
#include "dynarec.h"
#include "emu/x64emu_private.h"
#include "x64run.h"
#include "x64emu.h"
#include "box64stack.h"
#include "callback.h"
#include "emu/x64run_private.h"
#include "x64trace.h"
#include "dynablock.h"
#include "dynablock_private.h"
#include "dynarec_private.h"
#include "elfloader.h"
#include "bridge.h"

#include "dynarec_native.h"
#include "native_lock.h"

#include "custommem.h"
#include "khash.h"
#include "rbtree.h"

#ifdef CS2
#include <cs2c.h>
#endif

uint32_t X31_hash_code(void* addr, int len)
{
    if(!len) return 0;
    uint8_t* p = (uint8_t*)addr;
    int32_t h = *p;
    for (--len, ++p; len; --len, ++p) h = (h << 5) - h + (int32_t)*p;
    return (uint32_t)h;
}

dynablock_t* InvalidDynablock(dynablock_t* db, int need_lock)
{
    if(db) {
        if(db->gone)
            return NULL; // already in the process of deletion!
        dynarec_log(LOG_DEBUG, "InvalidDynablock(%p), db->block=%p x64=%p:%p already gone=%d\n", db, db->block, db->x64_addr, db->x64_addr+db->x64_size-1, db->gone);
        // remove jumptable without waiting
        setJumpTableDefault64(db->x64_addr);
        if(need_lock)
            mutex_lock(&my_context->mutex_dyndump);
        db->done = 0;
        db->gone = 1;
        uintptr_t db_size = db->x64_size;
        if(db_size && my_context) {
            uint32_t n = rb_get(my_context->db_sizes, db_size);
            if(n>1)
                rb_set(my_context->db_sizes, db_size, db_size+1, n-1);
            else
                rb_unset(my_context->db_sizes, db_size, db_size+1);
            if(db_size == my_context->max_db_size) {
                my_context->max_db_size = rb_get_righter(my_context->db_sizes);
                dynarec_log(LOG_INFO, "BOX64 Dynarec: lower max_db=%d\n", my_context->max_db_size);
            }
        }
        if(need_lock)
            mutex_unlock(&my_context->mutex_dyndump);
    }
    return db;
}

void FreeInvalidDynablock(dynablock_t* db, int need_lock)
{
    if(db) {
        if(!db->gone)
            return; // already in the process of deletion!
        dynarec_log(LOG_DEBUG, "FreeInvalidDynablock(%p), db->block=%p x64=%p:%p already gone=%d\n", db, db->block, db->x64_addr, db->x64_addr+db->x64_size-1, db->gone);
        if(need_lock)
            mutex_lock(&my_context->mutex_dyndump);
        FreeDynarecMap((uintptr_t)db->actual_block);
        customFree(db);
        if(need_lock)
            mutex_unlock(&my_context->mutex_dyndump);
    }
}

void FreeDynablock(dynablock_t* db, int need_lock)
{
    if(db) {
        if(db->gone)
            return; // already in the process of deletion!
        dynarec_log(LOG_DEBUG, "FreeDynablock(%p), db->block=%p x64=%p:%p already gone=%d\n", db, db->block, db->x64_addr, db->x64_addr+db->x64_size-1, db->gone);
        // remove jumptable without waiting
        setJumpTableDefault64(db->x64_addr);
        if(need_lock)
            mutex_lock(&my_context->mutex_dyndump);
        dynarec_log(LOG_DEBUG, " -- FreeDyrecMap(%p, %d)\n", db->actual_block, db->size);
        db->done = 0;
        db->gone = 1;
        uintptr_t db_size = db->x64_size;
        if(db_size && my_context) {
            uint32_t n = rb_get(my_context->db_sizes, db_size);
            if(n>1)
                rb_set(my_context->db_sizes, db_size, db_size+1, n-1);
            else
                rb_unset(my_context->db_sizes, db_size, db_size+1);
            if(db_size == my_context->max_db_size) {
                my_context->max_db_size = rb_get_righter(my_context->db_sizes);
                dynarec_log(LOG_INFO, "BOX64 Dynarec: lower max_db=%d\n", my_context->max_db_size);
            }
        }
        if(db->previous)
            FreeInvalidDynablock(db->previous, 0);
        FreeDynarecMap((uintptr_t)db->actual_block);
        customFree(db);
        if(need_lock)
            mutex_unlock(&my_context->mutex_dyndump);
    }
}



void MarkDynablock(dynablock_t* db)
{
    if(db) {
        dynarec_log(LOG_DEBUG, "MarkDynablock %p %p-%p\n", db, db->x64_addr, db->x64_addr+db->x64_size-1);
        if(!setJumpTableIfRef64(db->x64_addr, db->jmpnext, db->block)) {
            dynablock_t* old = db;
            db = getDB((uintptr_t)old->x64_addr);
            if(!old->gone && db!=old) {
                printf_log(LOG_INFO, "Warning, couldn't mark block as dirty for %p, block=%p, current_block=%p\n", old->x64_addr, old, db);
                // the block is lost, need to invalidate it...
                old->gone = 1;
                old->done = 0;
                if(!db || db->previous)
                    FreeInvalidDynablock(old, 1);
                else
                    db->previous = old;
            }
        }
    }
}

static int IntervalIntersects(uintptr_t start1, uintptr_t end1, uintptr_t start2, uintptr_t end2)
{
    if(start1 > end2 || start2 > end1)
        return 0;
    return 1;
}

void MarkRangeDynablock(dynablock_t* db, uintptr_t addr, uintptr_t size)
{
    // Mark will try to find *any* blocks that intersect the range to mark
    if(!db)
        return;
    dynarec_log(LOG_DEBUG, "MarkRangeDynablock %p-%p .. startdb=%p, sizedb=%p\n", (void*)addr, (void*)addr+size-1, (void*)db->x64_addr, (void*)db->x64_size);
    if(IntervalIntersects((uintptr_t)db->x64_addr, (uintptr_t)db->x64_addr+db->x64_size-1, addr, addr+size+1))
        MarkDynablock(db);
}

int FreeRangeDynablock(dynablock_t* db, uintptr_t addr, uintptr_t size)
{
    if(!db)
        return 1;

    int need_lock = my_context?1:0;
    if(IntervalIntersects((uintptr_t)db->x64_addr, (uintptr_t)db->x64_addr+db->x64_size-1, addr, addr+size+1)) {
        FreeDynablock(db, need_lock);
        return 0;
    }
    return 1;
}

dynablock_t *AddNewDynablock(uintptr_t addr)
{
    dynablock_t* block;
    // create and add new block
    dynarec_log(LOG_VERBOSE, "Ask for DynaRec Block creation @%p\n", (void*)addr);
    block = (dynablock_t*)customCalloc(1, sizeof(dynablock_t));
    return block;
}

//TODO: move this to dynrec_arm.c and track allocated structure to avoid memory leak
__thread JUMPBUFF dynarec_jmpbuf;
#ifdef ANDROID
#define DYN_JMPBUF dynarec_jmpbuf
#else
#define DYN_JMPBUF &dynarec_jmpbuf
#endif

void cancelFillBlock()
{
    longjmp(DYN_JMPBUF, 1);
}

/* 
    return NULL if block is not found / cannot be created. 
    Don't create if create==0
*/
static dynablock_t* internalDBGetBlock(x64emu_t* emu, uintptr_t addr, uintptr_t filladdr, int create, int need_lock, int is32bits)
{
#ifdef CS2
begin:
#endif
    if(hasAlternate((void*)addr))
        return NULL;
    dynablock_t* block = getDB(addr);
    if(block || !create)
        return block;

    if(need_lock) {
        if(box64_dynarec_wait) {
            mutex_lock(&my_context->mutex_dyndump);
        } else {
            if(mutex_trylock(&my_context->mutex_dyndump))   // FillBlock not available for now
                return NULL;
        }
        block = getDB(addr);    // just in case
        if(block) {
            mutex_unlock(&my_context->mutex_dyndump);
            return block;
        }
    }

#ifdef CS2
    if (box64_cs2c && box64_cs2c_preload && elf_test_and_set_preloaded_from_addr(addr) == 0) {
        // For each cached guest code block:
        // 1. Check if the block is already in DB. If it is, skip it.
        // 2. Check if it is identical to the block at the same address. If it is not, skip it.
        // 3. Create a new dynablock according to the cache block, record the start/end address
        //    of the block. Note that **do not flush icache**.
        // 
        // After all cached blocks are processed, flush icache for the range of start/end address.

        uintptr_t elf_delta;
        const char* elf_path = elf_info_from_addr(addr, &elf_delta);
        assert(elf_path != NULL);

        // Preload: Step 1, 2, 3.
        cs2c_preload_ctx ctx = (cs2c_preload_ctx) {
            .elf_path = elf_path,
            .is32bits = is32bits,
            .need_lock = need_lock,
            .delta = elf_delta,
            .count = 0,
            .start = NULL,
            .end = NULL,
        };
        cs2c_for_each_blocks(elf_path, &ctx, PreloadBlock64);

        // Flush icache.
        if (ctx.start != NULL && ctx.end != NULL) {
            assert(ctx.start <= ctx.end);
            __clear_cache(ctx.start, ctx.end);
            printf_log(LOG_INFO, "Preload %d blocks for %s\n", ctx.count, elf_path);
        }

        // Release the lock and go back to the beginning.
        if (need_lock) {
            mutex_unlock(&my_context->mutex_dyndump);
        }

        goto begin;
    }
#endif

    block = AddNewDynablock(addr);

    // fill the block
    block->x64_addr = (void*)addr;
    if(sigsetjmp(DYN_JMPBUF, 1)) {
        printf_log(LOG_INFO, "FillBlock at %p triggered a segfault, canceling\n", (void*)addr);
        FreeDynablock(block, 0);
        if(need_lock)
            mutex_unlock(&my_context->mutex_dyndump);
        return NULL;
    }
#ifdef CS2
    int use_cache = 1;
fill_block_retry:
    void* ret = FillBlock64(block, filladdr, (addr==filladdr)?0:1, is32bits, use_cache);
#else
    void* ret = FillBlock64(block, filladdr, (addr==filladdr)?0:1, is32bits);
#endif
    if(!ret) {
        dynarec_log(LOG_DEBUG, "Fillblock of block %p for %p returned an error\n", block, (void*)addr);
        customFree(block);
        block = NULL;
    }
#ifdef CS2
    else if (ret == (void*)(-1)) {
        dynarec_log(LOG_DEBUG, "Fillblock of block %p for %p return code indicating a need to retry without cache\n", block, (void*)addr);
        use_cache = 0;
        goto fill_block_retry;
    }
#endif
    // check size
    if(block) {
        // fill-in jumptable
        if(!addJumpTableIfDefault64(block->x64_addr, block->dirty?block->jmpnext:block->block)) {
            FreeDynablock(block, 0);
            block = getDB(addr);
            MarkDynablock(block);   // just in case...
        } else {
            if(block->x64_size) {
                if(block->x64_size>my_context->max_db_size) {
                    my_context->max_db_size = block->x64_size;
                    dynarec_log(LOG_INFO, "BOX64 Dynarec: higher max_db=%d\n", my_context->max_db_size);
                }
                block->done = 1;    // don't validate the block if the size is null, but keep the block
                rb_set(my_context->db_sizes, block->x64_size, block->x64_size+1, rb_get(my_context->db_sizes, block->x64_size)+1);
            }
        }
    }
    if(need_lock)
        mutex_unlock(&my_context->mutex_dyndump);

    dynarec_log(LOG_DEBUG, "%04d| --- DynaRec Block created @%p:%p (%p, 0x%x bytes)\n", GetTID(), (void*)addr, (void*)(addr+((block)?block->x64_size:1)-1), (block)?block->block:0, (block)?block->size:0);

    return block;
}

dynablock_t* DBGetBlock(x64emu_t* emu, uintptr_t addr, int create, int is32bits)
{
    if(isInHotPage(addr))
        return NULL;
    dynablock_t *db = internalDBGetBlock(emu, addr, addr, create, 1, is32bits);
    if(db && db->done && db->block && getNeedTest(addr)) {
        if(db->always_test)
            sched_yield();  // just calm down...
        uint32_t hash = X31_hash_code(db->x64_addr, db->x64_size);
        int need_lock = mutex_trylock(&my_context->mutex_dyndump);
        if(hash!=db->hash) {
            db->done = 0;   // invalidating the block
            dynarec_log(LOG_DEBUG, "Invalidating block %p from %p:%p (hash:%X/%X, always_test:%d) for %p\n", db, db->x64_addr, db->x64_addr+db->x64_size-1, hash, db->hash, db->always_test,(void*)addr);
            // Free db, it's now invalid!
            dynablock_t* old = InvalidDynablock(db, need_lock);
            // start again... (will create a new block)
            db = internalDBGetBlock(emu, addr, addr, create, need_lock, is32bits);
            if(db) {
                if(db->previous)
                    FreeInvalidDynablock(db->previous, need_lock);
                db->previous = old;
            } else
                FreeInvalidDynablock(old, need_lock);
        } else {
            dynarec_log(LOG_DEBUG, "Validating block %p from %p:%p (hash:%X, always_test:%d) for %p\n", db, db->x64_addr, db->x64_addr+db->x64_size-1, db->hash, db->always_test, (void*)addr);
            if(db->always_test)
                protectDB((uintptr_t)db->x64_addr, db->x64_size);
            else
                protectDBJumpTable((uintptr_t)db->x64_addr, db->x64_size, db->block, db->jmpnext);
        }
        if(!need_lock)
            mutex_unlock(&my_context->mutex_dyndump);
    } 
    if(!db || !db->block || !db->done)
        emu->test.test = 0;
    return db;
}

dynablock_t* DBAlternateBlock(x64emu_t* emu, uintptr_t addr, uintptr_t filladdr, int is32bits)
{
    dynarec_log(LOG_DEBUG, "Creating AlternateBlock at %p for %p%s\n", (void*)addr, (void*)filladdr, is32bits?" 32bits":"");
    int create = 1;
    dynablock_t *db = internalDBGetBlock(emu, addr, filladdr, create, 1, is32bits);
    if(db && db->done && db->block && getNeedTest(filladdr)) {
        if(db->always_test)
            sched_yield();  // just calm down...
        int need_lock = mutex_trylock(&my_context->mutex_dyndump);
        uint32_t hash = X31_hash_code(db->x64_addr, db->x64_size);
        if(hash!=db->hash) {
            db->done = 0;   // invalidating the block
            dynarec_log(LOG_DEBUG, "Invalidating alt block %p from %p:%p (hash:%X/%X) for %p\n", db, db->x64_addr, db->x64_addr+db->x64_size, hash, db->hash, (void*)addr);
            // Free db, it's now invalid!
            dynablock_t* old = InvalidDynablock(db, need_lock);
            // start again... (will create a new block)
            db = internalDBGetBlock(emu, addr, filladdr, create, need_lock, is32bits);
            if(db) {
                if(db->previous)
                    FreeInvalidDynablock(db->previous, need_lock);
                db->previous = old;
            } else
                FreeInvalidDynablock(old, need_lock);
        } else {
            if(db->always_test)
                protectDB((uintptr_t)db->x64_addr, db->x64_size);
            else
                protectDBJumpTable((uintptr_t)db->x64_addr, db->x64_size, db->block, db->jmpnext);
        }
        if(!need_lock)
            mutex_unlock(&my_context->mutex_dyndump);
    } 
    if(!db || !db->block || !db->done)
        emu->test.test = 0;
    return db;
}
