#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "debug.h"
#include "box64context.h"
#include "custommem.h"
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
#include "elfloader.h"

#include "dynarec_native.h"
#include "dynarec_arch.h"
#include "dynarec_next.h"

#ifdef CS2
#include <sys/time.h>
#include "cs2c.h"
#endif

void printf_x64_instruction(zydis_dec_t* dec, instruction_x64_t* inst, const char* name) {
    uint8_t *ip = (uint8_t*)inst->addr;
    if(ip[0]==0xcc && ip[1]=='S' && ip[2]=='C') {
        uintptr_t a = *(uintptr_t*)(ip+3);
        if(a==0) {
            dynarec_log(LOG_NONE, "%s%p: Exit x64emu%s\n", (box64_dynarec_dump>1)?"\e[01;33m":"", (void*)ip, (box64_dynarec_dump>1)?"\e[m":"");
        } else {
            dynarec_log(LOG_NONE, "%s%p: Native call to %p%s\n", (box64_dynarec_dump>1)?"\e[01;33m":"", (void*)ip, (void*)a, (box64_dynarec_dump>1)?"\e[m":"");
        }
    } else {
        if(dec) {
            dynarec_log(LOG_NONE, "%s%p: %s", (box64_dynarec_dump>1)?"\e[01;33m":"", ip, DecodeX64Trace(dec, inst->addr));
        } else {
            dynarec_log(LOG_NONE, "%s%p: ", (box64_dynarec_dump>1)?"\e[01;33m":"", ip);
            for(int i=0; i<inst->size; ++i) {
                dynarec_log(LOG_NONE, "%02X ", ip[i]);
            }
            dynarec_log(LOG_NONE, " %s", name);
        }
        // print Call function name if possible
        if(ip[0]==0xE8 || ip[0]==0xE9) { // Call / Jmp
            uintptr_t nextaddr = (uintptr_t)ip + 5 + *((int32_t*)(ip+1));
            printFunctionAddr(nextaddr, "=> ");
        } else if(ip[0]==0xFF) {
            if(ip[1]==0x25) {
                uintptr_t nextaddr = (uintptr_t)ip + 6 + *((int32_t*)(ip+2));
                printFunctionAddr(nextaddr, "=> ");
            }
        }
        // end of line and colors
        dynarec_log(LOG_NONE, "%s\n", (box64_dynarec_dump>1)?"\e[m":"");
    }
}

void add_next(dynarec_native_t *dyn, uintptr_t addr) {
    if(!box64_dynarec_bigblock)
        return;
    // exist?
    for(int i=0; i<dyn->next_sz; ++i)
        if(dyn->next[i]==addr)
            return;
    // put in a free slot
    for(int i=0; i<dyn->next_sz; ++i)
        if(!dyn->next[i]) {
            dyn->next[i] = addr;
            return;
        }
    // add slots
    if(dyn->next_sz == dyn->next_cap) {
        printf_log(LOG_NONE, "Warning, overallocating next\n");
    }
    dyn->next[dyn->next_sz++] = addr;
}
uintptr_t get_closest_next(dynarec_native_t *dyn, uintptr_t addr) {
    // get closest, but no addresses before
    uintptr_t best = 0;
    int i = 0;
    while((i<dyn->next_sz) && (best!=addr)) {
        if(dyn->next[i]) {
            if(dyn->next[i]<addr) { // remove the address, it's before current address
                dyn->next[i] = 0;
            } else {
                if((dyn->next[i]<best) || !best)
                    best = dyn->next[i];
            }
        }
        ++i;
    }
    return best;
}
void add_jump(dynarec_native_t *dyn, int ninst) {
    // add slots
    if(dyn->jmp_sz == dyn->jmp_cap) {
        printf_log(LOG_NONE, "Warning, overallocating jmps\n");
    }
    dyn->jmps[dyn->jmp_sz++] = ninst;
}
int get_first_jump(dynarec_native_t *dyn, int next) {
    if(next<0 || next>dyn->size)
        return -2;
    return get_first_jump_addr(dyn, dyn->insts[next].x64.addr);
}
int get_first_jump_addr(dynarec_native_t *dyn, uintptr_t next) {
    for(int i=0; i<dyn->jmp_sz; ++i)
        if(dyn->insts[dyn->jmps[i]].x64.jmp == next)
            return dyn->jmps[i];
    return -2;
}

#define PK(A) (*((uint8_t*)(addr+(A))))
int is_nops(dynarec_native_t *dyn, uintptr_t addr, int n)
{
    if(!n)
        return 1;
    if(PK(0)==0x90)
        return is_nops(dyn, addr+1, n-1);
    if(n>1 && PK(0)==0x66)  // if opcode start with 0x66, and there is more after, than is *can* be a NOP
        return is_nops(dyn, addr+1, n-1);
    if(n>2 && PK(0)==0x0f && PK(1)==0x1f && PK(2)==0x00)
        return is_nops(dyn, addr+3, n-3);
    if(n>2 && PK(0)==0x8d && PK(1)==0x76 && PK(2)==0x00)    // lea esi, [esi]
        return is_nops(dyn, addr+3, n-3);
    if(n>3 && PK(0)==0x0f && PK(1)==0x1f && PK(2)==0x40 && PK(3)==0x00)
        return is_nops(dyn, addr+4, n-4);
    if(n>3 && PK(0)==0x8d && PK(1)==0x74 && PK(2)==0x26 && PK(3)==0x00)
        return is_nops(dyn, addr+4, n-4);
    if(n>4 && PK(0)==0x0f && PK(1)==0x1f && PK(2)==0x44 && PK(3)==0x00 && PK(4)==0x00)
        return is_nops(dyn, addr+5, n-5);
    if(n>5 && PK(0)==0x8d && PK(1)==0xb6 && PK(2)==0x00 && PK(3)==0x00 && PK(4)==0x00 && PK(5)==0x00)
        return is_nops(dyn, addr+6, n-6);
    if(n>6 && PK(0)==0x0f && PK(1)==0x1f && PK(2)==0x80 && PK(3)==0x00 && PK(4)==0x00 && PK(5)==0x00 && PK(6)==0x00)
        return is_nops(dyn, addr+7, n-7);
    if(n>6 && PK(0)==0x8d && PK(1)==0xb4 && PK(2)==0x26 && PK(3)==0x00 && PK(4)==0x00 && PK(5)==0x00 && PK(6)==0x00) // lea esi, [esi+0]
        return is_nops(dyn, addr+7, n-7);
    if(n>7 && PK(0)==0x0f && PK(1)==0x1f && PK(2)==0x84 && PK(3)==0x00 && PK(4)==0x00 && PK(5)==0x00 && PK(6)==0x00 && PK(7)==0x00)
        return is_nops(dyn, addr+8, n-8);
    return 0;
}

// return size of next instruction, -1 is unknown
// not all instructions are setup
int next_instruction(dynarec_native_t *dyn, uintptr_t addr)
{
    uint8_t opcode = PK(0);
    uint8_t nextop;
    switch (opcode) {
        case 0x66:
            opcode = PK(1);
            switch(opcode) {
                case 0x90:
                    return 2;
            }
            break;
        case 0x81:
            nextop = PK(1);
            return fakeed(dyn, addr+2, 0, nextop)-addr + 4;
        case 0x83:
            nextop = PK(1);
            return fakeed(dyn, addr+2, 0, nextop)-addr + 1;
        case 0x84:
        case 0x85:
        case 0x88:
        case 0x89:
        case 0x8A:
        case 0x8B:
        case 0x8C:
        case 0x8D:
        case 0x8E:
        case 0x8F:
            nextop = PK(1);
            return fakeed(dyn, addr+2, 0, nextop)-addr;
        case 0x50:
        case 0x51:
        case 0x52:
        case 0x53:
        case 0x54:
        case 0x55:
        case 0x56:
        case 0x57:
        case 0x58:
        case 0x59:
        case 0x5A:
        case 0x5B:
        case 0x5C:
        case 0x5D:
        case 0x5E:
        case 0x5F:
        case 0x90:
        case 0x91:
        case 0x92:
        case 0x93:
        case 0x94:
        case 0x95:
        case 0x96:
        case 0x97:
        case 0x98:
        case 0x99:
        case 0x9B:
        case 0x9C:
        case 0x9D:
        case 0x9E:
        case 0x9F:
            return 1;
        case 0xA0:
        case 0xA1:
        case 0xA2:
        case 0xA3:
            return 5;
        case 0xB0:
        case 0xB1:
        case 0xB2:
        case 0xB3:
        case 0xB4:
        case 0xB5:
        case 0xB6:
        case 0xB7:
            return 2;
        case 0xB8:
        case 0xB9:
        case 0xBA:
        case 0xBB:
        case 0xBC:
        case 0xBD:
        case 0xBE:
        case 0xBF:
            return 5;
        case 0xFF:
            nextop = PK(1);
            switch((nextop>>3)&7) {
                case 0: // INC Ed
                case 1: //DEC Ed
                case 2: // CALL Ed
                case 4: // JMP Ed
                case 6: // Push Ed
                    return fakeed(dyn, addr+2, 0, nextop)-addr;
            }
            break;
        default:
            break;
    }
    return -1;
}
#undef PK

int is_instructions(dynarec_native_t *dyn, uintptr_t addr, int n)
{
    int i = 0;
    while(i<n) {
        int j=next_instruction(dyn, addr+i);
        if(j<=0) return 0;
        i+=j;
    }
    return (i==n)?1:0;
}

void addInst(instsize_t* insts, size_t* size, int x64_size, int native_size)
{
    // x64 instruction is <16 bytes
    int toadd;
    if(x64_size>native_size)
        toadd = 1 + x64_size/15;
    else
        toadd = 1 + native_size/15;
    while(toadd) {
        if(x64_size>15)
            insts[*size].x64 = 15;    
        else
            insts[*size].x64 = x64_size;
        x64_size -= insts[*size].x64;
        if(native_size>15)
            insts[*size].nat = 15;
        else
            insts[*size].nat = native_size;
        native_size -= insts[*size].nat;
        ++(*size);
        --toadd;
    }
}

// add a value to table64 (if needed) and gives back the imm19 to use in LDR_literal
int Table64(dynarec_native_t *dyn, uint64_t val, int pass)
{
    // find the value if already present
    int idx = -1;
    for(int i=0; i<dyn->table64size && (idx==-1); ++i)
        if(dyn->table64[i] == val)
            idx = i;
    // not found, add it
    if(idx==-1) {
        idx = dyn->table64size++;
        if(idx < dyn->table64cap)
            dyn->table64[idx] = val;
        else if(pass==3)
            printf_log(LOG_NONE, "Warning, table64 bigger than expected %d vs %d\n", idx, dyn->table64cap);
    }
    // calculate offset
    int delta = dyn->tablestart + idx*sizeof(uint64_t) - (uintptr_t)dyn->block;
    return delta;
}

static void recurse_mark_alive(dynarec_native_t* dyn, int i)
{
    if(dyn->insts[i].x64.alive)
        return;
    dyn->insts[i].x64.alive = 1;
    if(dyn->insts[i].x64.jmp && dyn->insts[i].x64.jmp_insts!=-1)
        recurse_mark_alive(dyn, dyn->insts[i].x64.jmp_insts);
    if(i<dyn->size-1 && dyn->insts[i].x64.has_next)
        recurse_mark_alive(dyn, i+1);
}

static int sizePredecessors(dynarec_native_t* dyn)
{
    int pred_sz = 1;    // to be safe
    // compute total size of predecessor to allocate the array
    // mark alive...
    recurse_mark_alive(dyn, 0);
    // first compute the jumps
    int jmpto;
    for(int i=0; i<dyn->size; ++i) {
        if(dyn->insts[i].x64.alive && dyn->insts[i].x64.jmp && ((jmpto=dyn->insts[i].x64.jmp_insts)!=-1)) {
            pred_sz++;
            dyn->insts[jmpto].pred_sz++;
        }
    }
    // remove "has_next" from orphan branch
    for(int i=0; i<dyn->size-1; ++i) {
        if(dyn->insts[i].x64.has_next && !dyn->insts[i+1].x64.alive)
            dyn->insts[i].x64.has_next = 0;
    }
    // second the "has_next"
    for(int i=0; i<dyn->size-1; ++i) {
        if(dyn->insts[i].x64.has_next) {
            pred_sz++;
            dyn->insts[i+1].pred_sz++;
        }
    }
    return pred_sz;
}
static void fillPredecessors(dynarec_native_t* dyn)
{
    // fill pred pointer
    int* p = dyn->predecessor;
    for(int i=0; i<dyn->size; ++i) {
        dyn->insts[i].pred = p;
        p += dyn->insts[i].pred_sz;
        dyn->insts[i].pred_sz=0;  // reset size, it's reused to actually fill pred[]
    }
    // fill pred
    for(int i=0; i<dyn->size; ++i) if(dyn->insts[i].x64.alive) {
        if((i!=dyn->size-1) && dyn->insts[i].x64.has_next)
            dyn->insts[i+1].pred[dyn->insts[i+1].pred_sz++] = i;
        if(dyn->insts[i].x64.jmp && (dyn->insts[i].x64.jmp_insts!=-1)) {
            int j = dyn->insts[i].x64.jmp_insts;
            dyn->insts[j].pred[dyn->insts[j].pred_sz++] = i;
        }
    }
}

// updateNeed for the current block. recursive function that goes backward
static int updateNeed(dynarec_native_t* dyn, int ninst, uint8_t need) {
    while (ninst>=0) {
        // need pending but instruction is only a subset: remove pend and use an X_ALL instead
        need |= dyn->insts[ninst].x64.need_after;
        if((need&X_PEND) && (dyn->insts[ninst].x64.state_flags==SF_SUBSET || dyn->insts[ninst].x64.state_flags==SF_SET || dyn->insts[ninst].x64.state_flags==SF_SET_NODF)) {
            need &=~X_PEND;
            need |= X_ALL;
        }
        if((need&X_PEND) && dyn->insts[ninst].x64.state_flags==SF_SUBSET_PENDING) {
            need |= X_ALL&~(dyn->insts[ninst].x64.set_flags);
        }
        dyn->insts[ninst].x64.gen_flags = need&dyn->insts[ninst].x64.set_flags;
        if((need&X_PEND) && (dyn->insts[ninst].x64.state_flags&SF_PENDING))
            dyn->insts[ninst].x64.gen_flags |= X_PEND;
        dyn->insts[ninst].x64.need_after = need;
        need = dyn->insts[ninst].x64.need_after&~dyn->insts[ninst].x64.gen_flags;

        if(dyn->insts[ninst].x64.may_set)
            need |= dyn->insts[ninst].x64.gen_flags;    // forward the flags
        else if((need&X_PEND) && (dyn->insts[ninst].x64.set_flags&SF_PENDING))
            need &=~X_PEND;         // Consume X_PEND if relevant
        need |= dyn->insts[ninst].x64.use_flags;
        if(dyn->insts[ninst].x64.need_before == need)
            return ninst - 1;
        dyn->insts[ninst].x64.need_before = need;
        if(dyn->insts[ninst].x64.barrier&BARRIER_FLAGS) {
            need = need?X_PEND:0;
        }
        int ok = 0;
        for(int i=0; i<dyn->insts[ninst].pred_sz; ++i) {
            if(dyn->insts[ninst].pred[i] == ninst-1)
                ok = 1;
            else
                updateNeed(dyn, dyn->insts[ninst].pred[i], need);
        }
        --ninst;
        if(!ok)
            return ninst;
    }
    return ninst;
}

static void updateYmm0s(dynarec_native_t* dyn, int ninst, int max_ninst_reached) {
    int can_incr = ninst == max_ninst_reached; // Are we the top-level call?
    int ok = 1;
    while ((can_incr || ok) && ninst<dyn->size) {
        //if(box64_dynarec_dump) dynarec_log(LOG_NONE, "update ninst=%d (%d): can_incr=%d\n", ninst, max_ninst_reached, can_incr);
        uint16_t new_purge_ymm, new_ymm0_in, new_ymm0_out;

        if (dyn->insts[ninst].pred_sz && dyn->insts[ninst].x64.alive) {
            // The union of the empty set is empty (0), the intersection is the universe (-1)
            // The first instruction is the entry point, which has a virtual pred with ymm0_out = 0
            // Similarly, float barriers reset ymm0s
            uint16_t ymm0_union = 0;
            uint16_t ymm0_inter = (ninst && !(dyn->insts[ninst].x64.barrier & BARRIER_FLOAT)) ? ((uint16_t)-1) : (uint16_t)0;
            for (int i = 0; i < dyn->insts[ninst].pred_sz; ++i) {
                int pred = dyn->insts[ninst].pred[i];
                //if(box64_dynarec_dump) dynarec_log(LOG_NONE, "\twith pred[%d] = %d", i, pred);
                if (pred >= max_ninst_reached) {
                    //if(box64_dynarec_dump) dynarec_log(LOG_NONE, " (skipped)\n");
                    continue;
                }

                int pred_out = dyn->insts[pred].x64.has_callret ? 0 : dyn->insts[pred].ymm0_out;
                //if(box64_dynarec_dump) dynarec_log(LOG_NONE, " ~> %04X\n", pred_out);
                ymm0_union |= pred_out;
                ymm0_inter &= pred_out;
            }
            //if(box64_dynarec_dump) dynarec_log(LOG_NONE, "\t=> %04X,%04X\n", ymm0_union, ymm0_inter);
            // Notice the default values yield something coherent here (if all pred are after ninst)
            new_purge_ymm = ymm0_union & ~ymm0_inter;
            new_ymm0_in = ymm0_inter;
            new_ymm0_out = (ymm0_inter | dyn->insts[ninst].ymm0_add) & ~dyn->insts[ninst].ymm0_sub;

            if ((dyn->insts[ninst].purge_ymm != new_purge_ymm) || (dyn->insts[ninst].ymm0_in != new_ymm0_in) || (dyn->insts[ninst].ymm0_out != new_ymm0_out)) {
                // Need to update self and next(s)
                dyn->insts[ninst].purge_ymm = new_purge_ymm;
                dyn->insts[ninst].ymm0_in = new_ymm0_in;
                dyn->insts[ninst].ymm0_out = new_ymm0_out;

                if (can_incr) {
                    // We always have ninst == max_ninst_reached when can_incr == 1
                    ++max_ninst_reached;
                } else {
                    // We need to stop here if the opcode has no "real" next or if we reached the ninst of the toplevel
                    ok = (max_ninst_reached - 1 != ninst) && dyn->insts[ninst].x64.has_next && !dyn->insts[ninst].x64.has_callret;
                }

                int jmp = (dyn->insts[ninst].x64.jmp)?dyn->insts[ninst].x64.jmp_insts:-1;
                if((jmp!=-1) && (jmp < max_ninst_reached)) {
                    //if(box64_dynarec_dump) dynarec_log(LOG_NONE, "\t! jump to %d\n", jmp);
                    // The jump goes before the last instruction reached, update the destination
                    // If this is the top level call, this means the jump goes backward (jmp != ninst)
                    // Otherwise, since we don't update all instructions, we may miss the update (don't use jmp < ninst)
                    updateYmm0s(dyn, jmp, max_ninst_reached);
                }
            } else {
                if (can_incr) {
                    // We always have ninst == max_ninst_reached when can_incr == 1
                    ++max_ninst_reached;

                    // Also update jumps to before (they are skipped otherwise)
                    int jmp = (dyn->insts[ninst].x64.jmp)?dyn->insts[ninst].x64.jmp_insts:-1;
                    if((jmp!=-1) && (jmp < max_ninst_reached)) {
                        //if(box64_dynarec_dump) dynarec_log(LOG_NONE, "\t! jump to %d\n", jmp);
                        updateYmm0s(dyn, jmp, max_ninst_reached);
                    }
                } else {
                    // We didn't update anything, we can leave
                    ok = 0;
                }
            }
        } else if (can_incr) {
            // We always have ninst == max_ninst_reached when can_incr == 1
            ++max_ninst_reached;
        } else {
            // We didn't update anything, we can leave
            ok = 0;
        }
        ++ninst;
    }
}

void* current_helper = NULL;
static int static_jmps[MAX_INSTS+2];
static uintptr_t static_next[MAX_INSTS+2];
static uint64_t static_table64[(MAX_INSTS+3)/4];
static instruction_native_t static_insts[MAX_INSTS+2] = {0};

#ifdef CS2
static int static_jmps_bkp[MAX_INSTS+2];
static uintptr_t static_next_bkp[MAX_INSTS+2];
static uint64_t static_table64_bkp[(MAX_INSTS+3)/4];
static instruction_native_t static_insts_bkp[MAX_INSTS+2] = {0};
#endif

// TODO: ninst could be a uint16_t instead of an int, that could same some temp. memory

void CancelBlock64(int need_lock)
{
    if(need_lock)
        mutex_lock(&my_context->mutex_dyndump);
    dynarec_native_t* helper = (dynarec_native_t*)current_helper;
    if(helper) {
        if(helper->dynablock && helper->dynablock->actual_block) {
            FreeDynarecMap((uintptr_t)helper->dynablock->actual_block);
            helper->dynablock->actual_block = NULL;
        }
    }
    current_helper = NULL;
    if(need_lock)
        mutex_unlock(&my_context->mutex_dyndump);
}

uintptr_t native_pass0(dynarec_native_t* dyn, uintptr_t addr, int alternate, int is32bits);
uintptr_t native_pass1(dynarec_native_t* dyn, uintptr_t addr, int alternate, int is32bits);
uintptr_t native_pass2(dynarec_native_t* dyn, uintptr_t addr, int alternate, int is32bits);
uintptr_t native_pass3(dynarec_native_t* dyn, uintptr_t addr, int alternate, int is32bits);
uintptr_t native_pass4(dynarec_native_t* dyn, uintptr_t addr, int alternate, int is32bits);

void* CreateEmptyBlock(dynablock_t* block, uintptr_t addr) {
    block->isize = 0;
    block->done = 0;
    size_t sz = 4*sizeof(void*);
    void* actual_p = (void*)AllocDynarecMap(sz);
    void* p = actual_p + sizeof(void*);
    if(actual_p==NULL) {
        dynarec_log(LOG_INFO, "AllocDynarecMap(%p, %zu) failed, canceling block\n", block, sz);
        CancelBlock64(0);
        return NULL;
    }
    block->size = sz;
    block->actual_block = actual_p;
    block->block = p;
    block->jmpnext = p;
    *(dynablock_t**)actual_p = block;
    *(void**)(p+2*sizeof(void*)) = native_epilog;
    CreateJmpNext(block->jmpnext, p+2*sizeof(void*));
    // all done...
    __clear_cache(actual_p, actual_p+sz);   // need to clear the cache before execution...
    return block;
}

#ifdef CS2
typedef struct {
    size_t real_native_size;
    int alternate;
    size_t native_size;
    size_t table64_size;
    size_t real_insts_size;
    size_t insts_rsize;
    int block_isize;
    uint8_t block_always_test;
    uint8_t block_dirty;
} cs2c_meta_t;

#define DIFF(x) \
    if(origin->x != cache->x) { \
        diff = 1; \
        dynarec_log(LOG_NONE,"block '" #x "' mismatch: %x vs %x\n", (uintptr_t)origin->x, (uintptr_t)cache->x); \
    }

#define DIFF_META(x) \
    if(origin_meta->x != cache_meta->x) { \
        diff = 1; \
        dynarec_log(LOG_NONE,"meta '" #x "' mismatch: %x vs %x\n", (uintptr_t)origin_meta->x, (uintptr_t)cache_meta->x); \
    }

static void diff_block(
    const char *path,
    uintptr_t addr,
    int alternate,
    dynablock_t* cache,
    size_t cache_sz,
    cs2c_meta_t* cache_meta,
    dynablock_t *origin,
    size_t origin_sz,
    cs2c_meta_t* origin_meta)
{
    int diff = 0;
    
    DIFF(previous)
    DIFF(size)
    DIFF(x64_addr)
    DIFF(x64_size)
    DIFF(hash)
    DIFF(done)
    DIFF(gone)
    DIFF(always_test)
    DIFF(dirty)
    DIFF(isize)

    if (origin_sz != cache_sz) {
        diff = 1;
        dynarec_log(LOG_NONE, "BLOCK SIZE mismatch: %zu vs %zu\n", origin_sz, cache_sz);
    }

    DIFF_META(native_size)
    DIFF_META(table64_size)
    DIFF_META(insts_rsize)
    DIFF_META(block_isize)
    DIFF_META(block_always_test)
    DIFF_META(block_dirty)

    // diff native code
    for (size_t i = 0; i < origin_meta->real_native_size && i < cache_meta->real_native_size; i += sizeof(uint32_t)) {
        uint32_t o = *(uint32_t*)((uintptr_t)origin->block + i);
        uint32_t c = *(uint32_t*)((uintptr_t)cache->block + i);
        if (o != c) {
            diff = 1;
            dynarec_log(LOG_NONE, "BLOCK CODE mismatch at %zu/[%zu, %zu]: %x vs %x\n", i, origin_meta->real_native_size, cache_meta->real_native_size, o, c);
        }
    }

    // diff table64
    for (size_t i = 0; i < origin_meta->table64_size && i < cache_meta->table64_size; i += sizeof(uint64_t)) {
        uint64_t o = *(uint64_t*)((uintptr_t)origin->block + origin_meta->native_size + i);
        uint64_t c = *(uint64_t*)((uintptr_t)cache->block + cache_meta->native_size + i);
        if (o != c) {
            diff = 1;
            dynarec_log(LOG_NONE, "BLOCK TABLE64 mismatch at %zu/[%zu, %zu]: %lx vs %lx\n", i, origin_meta->table64_size, cache_meta->table64_size, o, c);
        }
    }

    // diff instsize
    for (size_t i = 0; i < origin_meta->real_insts_size && i < cache_meta->real_insts_size; i += sizeof(instsize_t)) {
        instsize_t *o = (instsize_t*)((uintptr_t)origin->instsize + i);
        instsize_t *c = (instsize_t*)((uintptr_t)cache->instsize + i);
        if (o->x64 != c->x64) {
            diff = 1;
            dynarec_log(LOG_NONE, "BLOCK INSTSIZE (x64) mismatch at %zu/[%zu, %zu]: %x vs %x\n", i, origin_meta->real_insts_size, cache_meta->real_insts_size, o->x64, c->x64);
        }
        if (o->nat != c->nat) {
            diff = 1;
            dynarec_log(LOG_NONE, "BLOCK INSTSIZE (nat) mismatch at %zu/[%zu, %zu]: %x vs %x\n", i, origin_meta->real_insts_size, cache_meta->real_insts_size, o->nat, c->nat);
        }
    }

#if defined(ARM64) && ARM64
    const size_t empty_size = sizeof(uint32_t) * 2;
#elif defined(RV64) && RV64
    const size_t empty_size = sizeof(uint32_t) * 3;
#elif defined(LA64) && LA64
    const size_t empty_size = sizeof(uint32_t) * 3;
#endif

    for (
        size_t i = sizeof(void*) + origin_meta->native_size + origin_meta->table64_size;
        i < origin_sz - origin_meta->insts_rsize - empty_size - sizeof(void*) &&
        i < cache_sz - cache_meta->insts_rsize - empty_size - sizeof(void*);
        i += sizeof(uint32_t)
    ) {
        uint32_t o = *(uint32_t*)((uintptr_t)origin->actual_block + i);
        uint32_t c = *(uint32_t*)((uintptr_t)cache->actual_block + i);

        if (o != c) {
            diff = 1;
            dynarec_log(LOG_NONE, "BLOCK DATA mismatch at %zu/[%zu, %zu]: %x vs %x\n", i, origin_sz, cache_sz, o, c);
        }
    }

    if (diff) {
        dynarec_log(LOG_NONE, "%s/%p (alt=%s): BLOCK ERROR???? PLEASE CHECK!!!!\n", path, (void *)addr, alternate ? "true" : "false");
    }
}

#undef DIFF_META
#undef DIFF

#define BENCH_PASS0 0
#define BENCH_PASS1 1
#define BENCH_PASS2 2
#define BENCH_PASS3 3
#define BENCH_PASS4 4
#define BENCH_CS2C_LOOKUP_SUCC 5
#define BENCH_CS2C_LOOKUP_FAIL 6
#define BENCH_CACHE_FLUSH 7

void bench_output(int id, const struct timeval *st, const struct timeval *ed) {
    static FILE *output[8] = {NULL};
    if (!output[id]) {
        char name[256] = {0};
        sprintf(name, "bench_%d.txt", id);
        output[id] = fopen(name, "w");
    }
    
    struct timeval diff;
    timersub(ed, st, &diff);

    fprintf(output[id], "%ld.%06ld\n", diff.tv_sec, diff.tv_usec);
    fflush(output[id]);
}

#endif

void* FillBlock64(
    dynablock_t* block,
    uintptr_t addr,
    int alternate,
    int is32bits
#ifdef CS2
    , int use_cache
#endif
) {
    /*
        A Block must have this layout:

        0x0000..0x0007  : dynablock_t* : self
        0x0008..8+4*n   : actual Native instructions, (n is the total number)
        A ..    A+8*n   : Table64: n 64bits values
        B ..    B+7     : dynablock_t* : self (as part of JmpNext, that simulate another block)
        B+8 ..  B+15    : 2 Native code for jmpnext (or jmp epilog in case of empty block)
        B+16 .. B+23    : jmpnext (or jmp_epilog) address. jumpnext is used when the block needs testing
        B+24 .. B+31    : empty (in case an architecture needs more than 2 opcodes)
        B+32 .. B+32+sz : instsize (compressed array with each instruction length on x64 and native side)

    */
#ifdef CS2
    struct timeval st, ed;
#endif
    if(addr>=box64_nodynarec_start && addr<box64_nodynarec_end) {
        dynarec_log(LOG_INFO, "Create empty block in no-dynarec zone\n");
        return CreateEmptyBlock(block, addr);
    }
    if(current_helper) {
        dynarec_log(LOG_DEBUG, "Canceling dynarec FillBlock at %p as another one is going on\n", (void*)addr);
        return NULL;
    }
#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench pass 0 begin
        gettimeofday(&st, NULL);
    }
#endif
    // protect the 1st page
    protectDB(addr, 1);
    // init the helper
    dynarec_native_t helper = {0};
    current_helper = &helper;
    helper.dynablock = block;
    helper.start = addr;
    uintptr_t start = addr;
    helper.cap = MAX_INSTS;
    helper.insts = static_insts;
    helper.jmps = static_jmps;
    helper.jmp_cap = MAX_INSTS;
    helper.next = static_next;
    helper.next_cap = MAX_INSTS;
    helper.table64 = static_table64;
    helper.table64cap = sizeof(static_table64)/sizeof(uint64_t);
    // pass 0, addresses, x64 jump addresses, overall size of the block
    uintptr_t end = native_pass0(&helper, addr, alternate, is32bits);
    if(helper.abort) {
        if(box64_dynarec_dump || box64_dynarec_log)dynarec_log(LOG_NONE, "Abort dynablock on pass0\n");
        CancelBlock64(0);
        return NULL;
    }
    // basic checks
    if(!helper.size) {
        dynarec_log(LOG_INFO, "Warning, null-sized dynarec block (%p)\n", (void*)addr);
        CancelBlock64(0);
        return CreateEmptyBlock(block, addr);
    }
    if(!isprotectedDB(addr, 1)) {
        dynarec_log(LOG_INFO, "Warning, write on current page on pass0, aborting dynablock creation (%p)\n", (void*)addr);
        CancelBlock64(0);
        return NULL;
    }
    // protect the block of it goes over the 1st page
    if((addr&~(box64_pagesize-1))!=(end&~(box64_pagesize-1))) // need to protect some other pages too
        protectDB(addr, end-addr);  //end is 1byte after actual end
    // compute hash signature
    uint32_t hash = X31_hash_code((void*)addr, end-addr);
    // calculate barriers
    for(int ii=0; ii<helper.jmp_sz; ++ii) {
        int i = helper.jmps[ii];
        uintptr_t j = helper.insts[i].x64.jmp;
        helper.insts[i].x64.jmp_insts = -1;
        if(j<start || j>=end || j==helper.insts[i].x64.addr) {
            if(j==helper.insts[i].x64.addr) // if there is a loop on some opcode, make the block "always to tested"
                helper.always_test = 1;
            helper.insts[i].x64.need_after |= X_PEND;
        } else {
            // find jump address instruction
            int k=-1;
            int search = ((j>=helper.insts[0].x64.addr) && j<helper.insts[0].x64.addr+helper.isize)?1:0;
            int imin = 0;
            int imax = helper.size-1;
            int i2 = helper.size/2;
            // dichotomy search
            while(search) {
                if(helper.insts[i2].x64.addr == j) {
                    k = i2;
                    search = 0;
                } else if(helper.insts[i2].x64.addr>j) {
                    imax = i2;
                    i2 = (imax+imin)/2;
                } else {
                    imin = i2;
                    i2 = (imax+imin)/2;
                }
                if(search && (imax-imin)<2) {
                    search = 0;
                    if(helper.insts[imin].x64.addr==j)
                        k = imin;
                    else if(helper.insts[imax].x64.addr==j)
                        k = imax;
                }
            }
            /*for(int i2=0; i2<helper.size && k==-1; ++i2) {
                if(helper.insts[i2].x64.addr==j)
                    k=i2;
            }*/
            if(k!=-1) {
                if(!helper.insts[i].barrier_maybe)
                    helper.insts[k].x64.barrier |= BARRIER_FULL;
                helper.insts[i].x64.jmp_insts = k;
            }
        }
    }
    // no need for next anymore
    helper.next_sz = helper.next_cap = 0;
    helper.next = NULL;
    // fill predecessors with the jump address
    int alloc_size = sizePredecessors(&helper);
    helper.predecessor = (int*)alloca(alloc_size*sizeof(int));
    fillPredecessors(&helper);

    int pos = helper.size;
    while (pos>=0)
        pos = updateNeed(&helper, pos, 0);
    // remove fpu stuff on non-executed code
    for(int i=1; i<helper.size-1; ++i)
        if(!helper.insts[i].pred_sz) {
            int ii = i;
            while(ii<helper.size && !helper.insts[ii].pred_sz) {
                fpu_reset_ninst(&helper, ii);
                helper.insts[ii].ymm0_in = helper.insts[ii].ymm0_sub = helper.insts[ii].ymm0_add = helper.insts[ii].ymm0_out = helper.insts[ii].purge_ymm = 0;
                ++ii;
            }
            i = ii;
        }
    // remove trailling dead code
    while(helper.size && !helper.insts[helper.size-1].x64.alive) {
        helper.isize-=helper.insts[helper.size-1].x64.size;
        --helper.size;
    }
    if(!helper.size) {
        // NULL block after removing dead code, how is that possible?
        dynarec_log(LOG_INFO, "Warning, null-sized dynarec block after trimming dead code (%p)\n", (void*)addr);
        CancelBlock64(0);
        return CreateEmptyBlock(block, addr);
    }
    updateYmm0s(&helper, 0, 0);
#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench pass 0 end
        gettimeofday(&ed, NULL);
        bench_output(BENCH_PASS0, &st, &ed);

        // Bench pass 1 begin
        gettimeofday(&st, NULL);
    }
#endif
    // pass 1, float optimizations, first pass for flags
    native_pass1(&helper, addr, alternate, is32bits);
    if(helper.abort) {
        if(box64_dynarec_dump || box64_dynarec_log)dynarec_log(LOG_NONE, "Abort dynablock on pass1\n");
        CancelBlock64(0);
        return NULL;
    }

#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench pass 1 end
        gettimeofday(&ed, NULL);
        bench_output(BENCH_PASS1, &st, &ed);
    }
#endif

#ifdef CS2
    if (!use_cache) {
        goto slow_path;
    }
    int cs2c_cache_hit = 0;
    dynablock_t block_hit;
    size_t block_hit_sz;
    cs2c_meta_t meta_hit;
    bool cs2c_with_fast_path = box64_cs2c && end - addr > box64_cs2c_mark;
    if (!cs2c_with_fast_path) {
        goto slow_path;
    }
    uintptr_t elf_delta;
    const char* elf_path = elf_info_from_addr(addr, &elf_delta);
    cs2c_with_fast_path = elf_path != NULL;
    CodeSign code_sign;
    if (cs2c_with_fast_path) {
        if (box64_cs2c_bench) {
            // Bench CS2C begin
            gettimeofday(&st, NULL);
        }

        int ret;
        if ((ret = cs2c_calc_sign((void*)addr, end - addr, &code_sign)) < 0) {
            dynarec_log(LOG_NONE, "CS2 Failed to calculate sign: %d\n", ret);
            goto slow_path;
        }

        const cs2c_meta_t* host_meta;
        size_t host_meta_size;
        const void* host_code;
        size_t host_code_size;
        ret = cs2c_lookup(elf_path, addr - elf_delta, end - addr, &code_sign, (const void **)&host_meta, &host_meta_size, &host_code, &host_code_size);


        switch (ret) {
            case 0:
                if (box64_cs2c_bench) {
                    // Bench CS2C end
                    gettimeofday(&ed, NULL);
                    bench_output(BENCH_CS2C_LOOKUP_SUCC, &st, &ed);
                }
                // Cache Hit
                dynarec_log(LOG_DEBUG, "CS2 Cache Hit: %p\n", (void*)addr);
                break;
            case -ENOENT:
                if (box64_cs2c_bench) {
                    // Bench CS2C end
                    gettimeofday(&ed, NULL);
                    bench_output(BENCH_CS2C_LOOKUP_FAIL, &st, &ed);
                }
                // Cache Miss
                goto slow_path;
            default:
                // Error
                dynarec_log(LOG_NONE, "CS2 Failed to lookup: %d\n", ret);
                goto slow_path;
        }
        assert(host_meta_size == sizeof(cs2c_meta_t));
        assert(host_code_size == host_meta->native_size);

        dynarec_native_t helper_bkp;
        dynablock_t block_bkp;
        if (box64_cs2c_test) {
            // on stack values backup
            memcpy(&helper_bkp, &helper, sizeof(dynarec_native_t));
            memcpy(&block_bkp, block, sizeof(dynablock_t));

            // in data values backup
            memcpy(static_jmps_bkp, static_jmps, sizeof(static_jmps));
            memcpy(static_next_bkp, static_next, sizeof(static_next));
            memcpy(static_table64_bkp, static_table64, sizeof(static_table64));
            memcpy(static_insts_bkp, static_insts, sizeof(static_insts));
        }

        if (box64_cs2c_bench) {
            // Bench pass 4 begin
            gettimeofday(&st, NULL);
        }

        size_t sz = sizeof(void*) + host_meta->native_size + host_meta->table64_size * sizeof(uint64_t) + 4 * sizeof(void*) + host_meta->insts_rsize;
        void *actual_p = (void *)AllocDynarecMap(sz);
        block->block = actual_p + sizeof(void*);
        *(dynablock_t **)actual_p = block;

        memcpy(block->block, host_code, host_code_size);

        block->actual_block = actual_p;
        void *tablestart = block->block + host_meta->native_size;
        void *next = tablestart + host_meta->table64_size * sizeof(uint64_t);
        void *instsize = next + 4 * sizeof(void*);

        helper.block = block->block;
        helper.tablestart = (uintptr_t)tablestart;
        helper.jmp_next = (uintptr_t)next + sizeof(void*);
        helper.instsize = (instsize_t*)instsize;
        helper.table64cap = (next - tablestart) / sizeof(uint64_t);
        helper.table64 = (uint64_t*)tablestart;
        helper.native_size = 0;
        helper.table64size = 0; // reset table64 (but not the cap)
        helper.insts_size = 0;  // reset

        native_pass4(&helper, addr, alternate, is32bits);

        size_t rounded_native_size = (helper.native_size + 7) & ~7;
        if (rounded_native_size != host_meta->native_size) {
            dynarec_log(LOG_DEBUG, "CACHE ABORT!! CS2 Native size mismatch: %p (%zu vs %zu)\n", (void*)addr, rounded_native_size, host_meta->native_size);
            CancelBlock64(0);
            return (void*)(-1);
        }
        if (helper.table64size != helper.table64cap) {
            dynarec_log(LOG_DEBUG, "PRELOAD ABORT!! CS2 Table64 size mismatch: %p (%d vs %d)\n", (void*)addr, helper.table64size, helper.table64cap);
            CancelBlock64(0);
            return (void*)(-1);
        }

        block->size = sz;
        block->x64_addr = (void*)addr;
        block->x64_size = end - addr;
        block->hash = hash;
        block->always_test = host_meta->block_always_test;
        block->dirty = host_meta->block_dirty;
        block->isize = host_meta->block_isize;
        block->instsize = instsize;
        block->jmpnext = next + sizeof(void*);

        *(dynablock_t**)next = block;
        *(void**)(next + 3 * sizeof(void*)) = native_next;
        CreateJmpNext(block->jmpnext, next + 3 * sizeof(void*));

        if (box64_cs2c_bench) {
            // Bench pass 4 end
            gettimeofday(&ed, NULL);
            bench_output(BENCH_PASS4, &st, &ed);
        }

        cs2c_cache_hit = 1;
        if (box64_cs2c_test) {
            block_hit = *block;
            block_hit_sz = sz;
            meta_hit = *host_meta;
            // recover helper and block
            memcpy(&helper, &helper_bkp, sizeof(dynarec_native_t));
            memcpy(block, &block_bkp, sizeof(dynablock_t));

            // recover static values
            memcpy(static_jmps, static_jmps_bkp, sizeof(static_jmps));
            memcpy(static_next, static_next_bkp, sizeof(static_next));
            memcpy(static_table64, static_table64_bkp, sizeof(static_table64));
            memcpy(static_insts, static_insts_bkp, sizeof(static_insts));
            goto slow_path;
        }

        if (box64_cs2c_bench) {
            // Bench cache flush begin
            gettimeofday(&st, NULL);
        }
        __clear_cache(actual_p, actual_p + sz);
        if (box64_cs2c_bench) {
            // Bench cache flush end
            gettimeofday(&ed, NULL);
            bench_output(BENCH_CACHE_FLUSH, &st, &ed);
        }
        current_helper = NULL;
        dynarec_log(LOG_DEBUG, "CS2 Done, block %p\n", (void*)block->block);
        return (void*)block->block;
    }
slow_path:

    cs2c_meta_t host_metadata;
#endif

#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench pass 2 begin
        gettimeofday(&st, NULL);
    }
#endif
    // pass 2, instruction size
    native_pass2(&helper, addr, alternate, is32bits);
    if(helper.abort) {
        if(box64_dynarec_dump || box64_dynarec_log)dynarec_log(LOG_NONE, "Abort dynablock on pass2\n");
        CancelBlock64(0);
        return NULL;
    }

#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench pass 2 end
        gettimeofday(&ed, NULL);
        if (cs2c_with_fast_path) {
            bench_output(BENCH_PASS2, &st, &ed);
        }

        // Bench pass 3 begin
        gettimeofday(&st, NULL);
    }
#endif

#ifdef CS2
    if (cs2c_with_fast_path) {
        host_metadata.real_native_size = helper.native_size;
        host_metadata.real_insts_size = helper.insts_size;
        host_metadata.table64_size = helper.table64size;
    }
#endif
    // keep size of instructions for signal handling
    size_t insts_rsize = (helper.insts_size+2)*sizeof(instsize_t);
    insts_rsize = (insts_rsize+7)&~7;   // round the size...
    size_t native_size = (helper.native_size+7)&~7;   // round the size...
    // ok, now allocate mapped memory, with executable flag on
    size_t sz = sizeof(void*) + native_size + helper.table64size*sizeof(uint64_t) + 4*sizeof(void*) + insts_rsize;
    //           dynablock_t*     block (arm insts)            table64               jmpnext code       instsize
#ifdef CS2
    if (cs2c_with_fast_path) {
        host_metadata.alternate = alternate;
    }
#endif
    void* actual_p = (void*)AllocDynarecMap(sz);
    void* p = (void*)(((uintptr_t)actual_p) + sizeof(void*));
    void* tablestart = p + native_size;
    void* next = tablestart + helper.table64size*sizeof(uint64_t);
    void* instsize = next + 4*sizeof(void*);
    if(actual_p==NULL) {
        dynarec_log(LOG_INFO, "AllocDynarecMap(%p, %zu) failed, canceling block\n", block, sz);
        CancelBlock64(0);
        return NULL;
    }
    helper.block = p;
    block->actual_block = actual_p;
    helper.native_start = (uintptr_t)p;
    helper.tablestart = (uintptr_t)tablestart;
    helper.jmp_next = (uintptr_t)next+sizeof(void*);
    helper.instsize = (instsize_t*)instsize;
    *(dynablock_t**)actual_p = block;
    helper.table64cap = helper.table64size;
    helper.table64 = (uint64_t*)helper.tablestart;
    // pass 3, emit (log emit native opcode)
    if(box64_dynarec_dump) {
        dynarec_log(LOG_NONE, "%s%04d|Emitting %zu bytes for %u %s bytes", (box64_dynarec_dump>1)?"\e[01;36m":"", GetTID(), helper.native_size, helper.isize, is32bits?"x86":"x64"); 
        printFunctionAddr(helper.start, " => ");
        dynarec_log(LOG_NONE, "%s\n", (box64_dynarec_dump>1)?"\e[m":"");
    }
    int oldtable64size = helper.table64size;
    size_t oldnativesize = helper.native_size;
    size_t oldinstsize = helper.insts_size;
    int oldsize= helper.size;
    helper.native_size = 0;
    helper.table64size = 0; // reset table64 (but not the cap)
    helper.insts_size = 0;  // reset
    native_pass3(&helper, addr, alternate, is32bits);
    if(helper.abort) {
        if(box64_dynarec_dump || box64_dynarec_log)dynarec_log(LOG_NONE, "Abort dynablock on pass3\n");
        CancelBlock64(0);
        return NULL;
    }
    // no need for jmps anymore
    helper.jmp_sz = helper.jmp_cap = 0;
    helper.jmps = NULL;
    // keep size of instructions for signal handling
    block->instsize = instsize;
    helper.table64 = NULL;
    helper.instsize = NULL;
    helper.predecessor = NULL;
    block->size = sz;
    block->isize = helper.size;
    block->block = p;
    block->jmpnext = next+sizeof(void*);
    block->always_test = helper.always_test;
    block->dirty = block->always_test;
#ifdef CS2
    if (cs2c_with_fast_path) {
        host_metadata.native_size = native_size;
        host_metadata.insts_rsize = insts_rsize;
        host_metadata.block_isize = block->isize;
    }
#endif
    *(dynablock_t**)next = block;
    *(void**)(next+3*sizeof(void*)) = native_next;
    CreateJmpNext(block->jmpnext, next+3*sizeof(void*));

#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench pass 3 end
        gettimeofday(&ed, NULL);
        if (cs2c_with_fast_path) {
            bench_output(BENCH_PASS3, &st, &ed);
        }
    }
#endif

    //block->x64_addr = (void*)start;
    block->x64_size = end-start;
    // all done...
#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench cache flush begin
        gettimeofday(&st, NULL);
    }
#endif
    __clear_cache(actual_p, actual_p+sz);   // need to clear the cache before execution...
#ifdef CS2
    if (box64_cs2c_bench) {
        // Bench cache flush end
        gettimeofday(&ed, NULL);
        bench_output(BENCH_CACHE_FLUSH, &st, &ed);
    }
#endif
    block->hash = X31_hash_code(block->x64_addr, block->x64_size);
    // Check if something changed, to abort if it is
    if((helper.abort || (block->hash != hash))) {
        dynarec_log(LOG_DEBUG, "Warning, a block changed while being processed hash(%p:%ld)=%x/%x\n", block->x64_addr, block->x64_size, block->hash, hash);
        CancelBlock64(0);
        return NULL;
    }
    if((oldnativesize!=helper.native_size) || (oldtable64size<helper.table64size)) {
        printf_log(LOG_NONE, "BOX64: Warning, size difference in block between pass2 (%zu, %d) & pass3 (%zu, %d)!\n", oldnativesize+oldtable64size*8, oldsize, helper.native_size+helper.table64size*8, helper.size);
        uint8_t *dump = (uint8_t*)helper.start;
        printf_log(LOG_NONE, "Dump of %d x64 opcodes:\n", helper.size);
        for(int i=0; i<helper.size; ++i) {
            printf_log(LOG_NONE, "%s%p:", (helper.insts[i].size2!=helper.insts[i].size)?"=====> ":"", dump);
            for(; dump<(uint8_t*)helper.insts[i+1].x64.addr; ++dump)
                printf_log(LOG_NONE, " %02X", *dump);
            printf_log(LOG_NONE, "\t%d -> %d", helper.insts[i].size2, helper.insts[i].size);
            if(helper.insts[i].ymm0_pass2 || helper.insts[i].ymm0_pass3)
                printf_log(LOG_NONE, "\t %04x -> %04x", helper.insts[i].ymm0_pass2, helper.insts[i].ymm0_pass3);
            printf_log(LOG_NONE, "\n");
        }
        printf_log(LOG_NONE, "Table64 \t%d -> %d\n", oldtable64size*8, helper.table64size*8);
        printf_log(LOG_NONE, " ------------\n");
        CancelBlock64(0);
        return NULL;
    }
    // ok, free the helper now
    //dynaFree(helper.insts);
    helper.insts = NULL;
    if(insts_rsize/sizeof(instsize_t)<helper.insts_size) {
        printf_log(LOG_NONE, "BOX64: Warning, insts_size difference in block between pass2 (%zu) and pass3 (%zu), allocated: %zu\n", oldinstsize, helper.insts_size, insts_rsize/sizeof(instsize_t));
    }
    if(!isprotectedDB(addr, end-addr)) {
        dynarec_log(LOG_DEBUG, "Warning, block unprotected while being processed %p:%ld, marking as need_test\n", block->x64_addr, block->x64_size);
        block->dirty = 1;
        //protectDB(addr, end-addr);
    }
    if(getProtection(addr)&PROT_NEVERCLEAN) {
        block->dirty = 1;
        block->always_test = 1;
    }
    if(block->always_test) {
        dynarec_log(LOG_DEBUG, "Note: block marked as always dirty %p:%ld\n", block->x64_addr, block->x64_size);
    }
    current_helper = NULL;
    //block->done = 1;

#ifdef CS2
    if (cs2c_with_fast_path) {
        host_metadata.block_always_test = block->always_test;
        host_metadata.block_dirty = block->dirty;
        if (box64_cs2c_test && cs2c_cache_hit) {
            diff_block(elf_path, addr, alternate, &block_hit, block_hit_sz, &meta_hit, block, sz, &host_metadata);
            // FIXME: FREE block hit?
        }
        if (!cs2c_cache_hit) {
            cs2c_sync(elf_path, addr - elf_delta, end - addr, &code_sign, &host_metadata, sizeof(host_metadata), p, host_metadata.native_size);
        }
    }
#endif
    return (void*)block;
}

#ifdef CS2
#include <setjmp.h>

#include "bridge.h"
#include "dynablock.h"
#include "rbtree.h"

int cs2c_preloading = 0;

void* PreloadFillBlock64(
    cs2c_preload_ctx* ctx,
    dynablock_t* block,
    uintptr_t addr,
    int alternate,
    int is32bits,
    const CacheTableDataRaw* cs2_block);

void PreloadBlock64(void* data, const CacheTableDataRaw* cs2_block)
{
    int err;
    dynablock_t* block;
    cs2c_preload_ctx* ctx = (cs2c_preload_ctx*)data;

    cs2c_preloading = 1;

    // Step 1: Check if the block is already in DB or should be ignored. If it is, skip it.
    void* start = (void*)cs2_block->guest_addr + ctx->delta;
    void* end = (void*)((uintptr_t)start + cs2_block->guest_size);

    if ((uintptr_t)start >= box64_nodynarec_start && (uintptr_t)start < box64_nodynarec_end) {
        return;
    }

    if (hasAlternate((void*)start) || getDB((uintptr_t)start)) {
        return;
    }

    // Step 2: Check if it is identical to the block at the same address. If it is not,
    //         skip it.
    CodeSign code_sign;
    if (sigsetjmp(DYN_JMPBUF, 1)) {
        dynarec_log(LOG_NONE, "Calculation of sign at %p triggered a segfault, skipping\n", start);
        return;
    }
    if ((err = cs2c_calc_sign(start, end - start, &code_sign)) < 0) {
        dynarec_log(LOG_NONE, "CS2 Failed to calculate sign: %d\n", err);
        return;
    }
    if (!cs2c_test_sign(&code_sign, cs2_block->guest_sign)) {
        dynarec_log(LOG_DEBUG, "CS2 Code sign mismatch\n");
        return;
    }

    // Step 3: Create a new dynablock according to the cache block, record the start/end
    //         address of the block. Note that **do not flush icache**.

    block = AddNewDynablock((uintptr_t)start);
    block->x64_addr = start;
    if (sigsetjmp(DYN_JMPBUF, 1)) {
        printf_log(LOG_INFO, "PreloadFillblock64 at %p triggered a segfault, canceling\n", start);
        FreeDynablock(block, 0);
        return;
    }
    cs2c_meta_t* meta = (cs2c_meta_t*)cs2_block->host_meta;
    assert(cs2_block->host_meta_len == sizeof(cs2c_meta_t));
    void* ret = PreloadFillBlock64(ctx, block, (uintptr_t)start, meta->alternate, ctx->is32bits, cs2_block);
    if (!ret) {
        dynarec_log(LOG_DEBUG, "PreloadFillblock64 of block %p for %p returned an error\n", block, start);
        customFree(block);
        block = NULL;
    }

    if (block) {
        // fill-in jumptable
        if (!addJumpTableIfDefault64(block->x64_addr, block->dirty ? block->jmpnext : block->block)) {
            FreeDynablock(block, 0);
            block = getDB((uintptr_t)start);
            MarkDynablock(block);
        } else {
            if (block->x64_size) {
                if (block->x64_size > my_context->max_db_size) {
                    my_context->max_db_size = block->x64_size;
                    dynarec_log(LOG_INFO, "BOX64 Dynarec: higher max_db=%d\n", my_context->max_db_size);
                }
                block->done = 1; // don't validate the block if the size is null, but keep the block
                rb_set(my_context->db_sizes, block->x64_size, block->x64_size + 1, rb_get(my_context->db_sizes, block->x64_size) + 1);
            }
        }
        // Finally, adjust start/end address in context
        if (!ctx->start || ctx->start > block->block) {
            ctx->start = block->block;
        }
        if (!ctx->end || ctx->end < block->block + block->size) {
            ctx->end = block->block + block->size;
        }
        ctx->count++;
    }

    cs2c_preloading = 0;
}

// Similar to FillBlock64, but the cached block is provided
void* PreloadFillBlock64(
    cs2c_preload_ctx* ctx,
    dynablock_t* block,
    uintptr_t addr,
    int alternate,
    int is32bits,
    const CacheTableDataRaw* cs2_block)
{
    if(addr>=box64_nodynarec_start && addr<box64_nodynarec_end) {
        dynarec_log(LOG_INFO, "Create empty block in no-dynarec zone\n");
        return CreateEmptyBlock(block, addr);
    }
    if(current_helper) {
        dynarec_log(LOG_DEBUG, "Canceling dynarec FillBlock at %p as another one is going on\n", (void*)addr);
        return NULL;
    }
    // protect the 1st page
    protectDB(addr, 1);
    // init the helper
    dynarec_native_t helper = {0};
    current_helper = &helper;
    helper.dynablock = block;
    helper.start = addr;
    uintptr_t start = addr;
    helper.cap = MAX_INSTS;
    helper.insts = static_insts;
    helper.jmps = static_jmps;
    helper.jmp_cap = MAX_INSTS;
    helper.next = static_next;
    helper.next_cap = MAX_INSTS;
    helper.table64 = static_table64;
    helper.table64cap = sizeof(static_table64)/sizeof(uint64_t);
    // pass 0, addresses, x64 jump addresses, overall size of the block
    uintptr_t end = native_pass0(&helper, addr, alternate, is32bits);
    if(helper.abort) {
        if(box64_dynarec_dump || box64_dynarec_log)dynarec_log(LOG_NONE, "Abort dynablock on pass0\n");
        CancelBlock64(0);
        return NULL;
    }
    // basic checks
    if(!helper.size) {
        dynarec_log(LOG_INFO, "Warning, null-sized dynarec block (%p)\n", (void*)addr);
        CancelBlock64(0);
        return CreateEmptyBlock(block, addr);
    }
    if(!isprotectedDB(addr, 1)) {
        dynarec_log(LOG_INFO, "Warning, write on current page on pass0, aborting dynablock creation (%p)\n", (void*)addr);
        CancelBlock64(0);
        return NULL;
    }
    // protect the block of it goes over the 1st page
    if((addr&~(box64_pagesize-1))!=(end&~(box64_pagesize-1))) // need to protect some other pages too
        protectDB(addr, end-addr);  //end is 1byte after actual end
    // compute hash signature
    uint32_t hash = X31_hash_code((void*)addr, end-addr);
    // calculate barriers
    for(int ii=0; ii<helper.jmp_sz; ++ii) {
        int i = helper.jmps[ii];
        uintptr_t j = helper.insts[i].x64.jmp;
        helper.insts[i].x64.jmp_insts = -1;
        if(j<start || j>=end || j==helper.insts[i].x64.addr) {
            if(j==helper.insts[i].x64.addr) // if there is a loop on some opcode, make the block "always to tested"
                helper.always_test = 1;
            helper.insts[i].x64.need_after |= X_PEND;
        } else {
            // find jump address instruction
            int k=-1;
            int search = ((j>=helper.insts[0].x64.addr) && j<helper.insts[0].x64.addr+helper.isize)?1:0;
            int imin = 0;
            int imax = helper.size-1;
            int i2 = helper.size/2;
            // dichotomy search
            while(search) {
                if(helper.insts[i2].x64.addr == j) {
                    k = i2;
                    search = 0;
                } else if(helper.insts[i2].x64.addr>j) {
                    imax = i2;
                    i2 = (imax+imin)/2;
                } else {
                    imin = i2;
                    i2 = (imax+imin)/2;
                }
                if(search && (imax-imin)<2) {
                    search = 0;
                    if(helper.insts[imin].x64.addr==j)
                        k = imin;
                    else if(helper.insts[imax].x64.addr==j)
                        k = imax;
                }
            }
            /*for(int i2=0; i2<helper.size && k==-1; ++i2) {
                if(helper.insts[i2].x64.addr==j)
                    k=i2;
            }*/
            if(k!=-1) {
                if(!helper.insts[i].barrier_maybe)
                    helper.insts[k].x64.barrier |= BARRIER_FULL;
                helper.insts[i].x64.jmp_insts = k;
            }
        }
    }
    // no need for next anymore
    helper.next_sz = helper.next_cap = 0;
    helper.next = NULL;
    // fill predecessors with the jump address
    int alloc_size = sizePredecessors(&helper);
    helper.predecessor = (int*)alloca(alloc_size*sizeof(int));
    fillPredecessors(&helper);

    int pos = helper.size;
    while (pos>=0)
        pos = updateNeed(&helper, pos, 0);
    // remove fpu stuff on non-executed code
    for(int i=1; i<helper.size-1; ++i)
        if(!helper.insts[i].pred_sz) {
            int ii = i;
            while(ii<helper.size && !helper.insts[ii].pred_sz) {
                fpu_reset_ninst(&helper, ii);
                helper.insts[ii].ymm0_in = helper.insts[ii].ymm0_sub = helper.insts[ii].ymm0_add = helper.insts[ii].ymm0_out = helper.insts[ii].purge_ymm = 0;
                ++ii;
            }
            i = ii;
        }
    // remove trailling dead code
    while(helper.size && !helper.insts[helper.size-1].x64.alive) {
        helper.isize-=helper.insts[helper.size-1].x64.size;
        --helper.size;
    }
    if(!helper.size) {
        // NULL block after removing dead code, how is that possible?
        dynarec_log(LOG_INFO, "Warning, null-sized dynarec block after trimming dead code (%p)\n", (void*)addr);
        CancelBlock64(0);
        return CreateEmptyBlock(block, addr);
    }
    updateYmm0s(&helper, 0, 0);

    // pass 1, float optimizations, first pass for flags
    native_pass1(&helper, addr, alternate, is32bits);
    if(helper.abort) {
        if(box64_dynarec_dump || box64_dynarec_log)dynarec_log(LOG_NONE, "Abort dynablock on pass1\n");
        CancelBlock64(0);
        return NULL;
    }

    // fetch the host code and meta, and fill the block
    const cs2c_meta_t* host_meta = (const cs2c_meta_t*)cs2_block->host_meta;
    size_t host_meta_size = cs2_block->host_meta_len;
    const void* host_code = cs2_block->host_code;
    size_t host_code_size = cs2_block->host_code_len;

    if (end - start != cs2_block->guest_size) {
        dynarec_log(LOG_DEBUG, "PRELOAD ABORT!! CS2 Block size mismatch: %p\n", (void*)addr);
        CancelBlock64(0);
        return NULL;
    }

    assert(start == cs2_block->guest_addr + ctx->delta);
    assert(host_meta_size == sizeof(cs2c_meta_t));
    assert(host_code_size == host_meta->native_size);

    size_t sz = sizeof(void*) + host_meta->native_size + host_meta->table64_size * sizeof(uint64_t) + 4 * sizeof(void*) + host_meta->insts_rsize;
    void *actual_p = (void *)AllocDynarecMap(sz);
    if (actual_p == NULL) {
        dynarec_log(LOG_INFO, "AllocDynarecMap(%p, %zu) failed, canceling block\n", block, sz);
        CancelBlock64(0);
        return NULL;
    }
    block->block = actual_p + sizeof(void*);
    *(dynablock_t **)actual_p = block;

    memcpy(block->block, host_code, host_code_size);

    block->actual_block = actual_p;
    void *tablestart = block->block + host_meta->native_size;
    void *next = tablestart + host_meta->table64_size * sizeof(uint64_t);

    helper.block = block->block;
    helper.tablestart = (uintptr_t)tablestart;
    helper.jmp_next = (uintptr_t)next + sizeof(void*);
    helper.instsize = (instsize_t*)(next + 4 * sizeof(void*));
    helper.table64cap = (next - tablestart) / sizeof(uint64_t);
    helper.table64 = (uint64_t*)tablestart;
    helper.native_size = 0;
    helper.table64size = 0; // reset table64 (but not the cap)
    helper.insts_size = 0;  // reset

    native_pass4(&helper, addr, alternate, is32bits);

    size_t rounded_native_size = (helper.native_size + 7) & ~7;
    if (rounded_native_size != host_meta->native_size) {
        dynarec_log(LOG_DEBUG, "PRELOAD ABORT!! CS2 Native size mismatch: %p (%zu vs %zu)\n", (void*)addr, rounded_native_size, host_meta->native_size);
        CancelBlock64(0);
        return NULL;
    }
    if (helper.table64size != helper.table64cap) {
        dynarec_log(LOG_DEBUG, "PRELOAD ABORT!! CS2 Table64 size mismatch: %p (%d vs %d)\n", (void*)addr, helper.table64size, helper.table64cap);
        CancelBlock64(0);
        return NULL;
    }

    block->size = sz;
    block->x64_addr = (void*)addr;
    block->x64_size = end - addr;
    block->hash = hash;
    block->always_test = host_meta->block_always_test;
    block->dirty = host_meta->block_dirty;
    block->isize = host_meta->block_isize;
    block->instsize = next + 4 * sizeof(void*);
    block->jmpnext = next + sizeof(void*);

    *(dynablock_t**)next = block;
    *(void**)(next + 3 * sizeof(void*)) = native_next;
    CreateJmpNext(block->jmpnext, next + 3 * sizeof(void*));

    current_helper = NULL;
    return (void*)block->block;
}
#endif
