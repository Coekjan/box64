#ifndef CS2C_H
#define CS2C_H

#include "generated/cs2s-ccapi.h"

void cs2c_init(void);
void cs2c_path_attach(const char* const* paths, size_t paths_len);
void cs2c_sync(
    const char* path,
    size_t guest_addr,
    size_t guest_size,
    const CodeSign* guest_sign,
    const void* host_meta,
    size_t host_meta_len,
    const void* host_code,
    size_t host_code_len);
int cs2c_lookup(
    const char* path,
    size_t guest_addr,
    size_t guest_size,
    const CodeSign* guest_sign,
    const void** host_meta_ptr,
    size_t* host_meta_size,
    const void** host_code_ptr,
    size_t* host_code_size);
int cs2c_calc_sign(const void* guest_code, size_t guest_size, CodeSign* guest_sign);
int cs2c_test_sign(const CodeSign *sign1, const CodeSign *sign2);
const void* cs2c_block_code(const CacheBlockHeader* block);
const void* cs2c_block_meta(const CacheBlockHeader* block);
int cs2c_for_each_blocks(
    const char* path,
    void* data,
    void (*callback)(void*, const CacheBlockHeader*));
void cs2c_exit(void);

typedef struct cs2c_preload_ctx {
    const char *elf_path;
    const int is32bits;
    const int need_lock;
    const uintptr_t delta;
    int count;
    void *start;
    void *end;
} cs2c_preload_ctx;

#endif
