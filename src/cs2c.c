#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "debug.h"
#include "generated/cs2s-ccapi.h"

static CommandQueueClientHandlePtr cs2s_cmdq;
static LookupRouterPtr cs2s_ro;

void cs2c_init(void)
{
    int ret;
    if ((ret = cs2s_cmdq_create("box64", &cs2s_cmdq)) != 0) {
        printf_log(LOG_NONE, "Failed to create command queue client: %d\n", ret);
        exit(1);
    }
    if ((ret = cs2s_cmdq_connect(cs2s_cmdq)) != 0) {
        printf_log(LOG_NONE, "Failed to connect to command queue server: %d\n", ret);
        exit(1);
    }
    if ((ret = cs2s_ro_create("box64", &cs2s_ro)) != 0) {
        printf_log(LOG_NONE, "Failed to create lookup router: %d\n", ret);
        exit(1);
    }
}

void cs2c_path_attach(const char* const* paths, size_t paths_len)
{
    if (cs2s_cmdq_paths_attach(cs2s_cmdq, paths, paths_len)) {
        printf_log(LOG_NONE, "Failed to attach paths to command queue client\n");
        exit(1);
    }
    while (cs2s_ro_attach(cs2s_ro, paths, paths_len)) {
        printf_log(LOG_DEBUG, "Failed to attach paths to lookup router. Sleep for 50 ms and retry\n");
        usleep(50000);
    }
}

void cs2c_sync(
    const char* path,
    size_t guest_addr,
    size_t guest_size,
    const CodeSign* guest_sign,
    const void* host_meta,
    size_t host_meta_len,
    const void* host_code,
    size_t host_code_len)
{
    int ret;
    if ((ret = cs2s_cmdq_sync(cs2s_cmdq, path, guest_addr, guest_size, guest_sign, host_meta, host_meta_len, host_code, host_code_len)) != 0) {
        printf_log(LOG_NONE, "Failed to synchronize cache to command queue server: %d\n", ret);
    }
}

int cs2c_lookup(
    const char* path,
    size_t guest_addr,
    size_t guest_size,
    const CodeSign* guest_sign,
    const void** host_meta_ptr,
    size_t* host_meta_size,
    const void** host_code_ptr,
    size_t* host_code_size)
{
    int ret;
    if ((ret = cs2s_ro_lookup(cs2s_ro, path, guest_addr, guest_size, guest_sign, host_meta_ptr, host_meta_size, host_code_ptr, host_code_size)) == -EINVAL) {
        printf_log(LOG_NONE, "Failed to lookup address in lookup router: %d\n", ret);
    }
    if ((ret & 0xf0000000) == 0x80000000) {
        cs2c_path_attach((const char*[]) { path }, 1);
        if ((ret = cs2s_ro_lookup(cs2s_ro, path, guest_addr, guest_size, guest_sign, host_meta_ptr, host_meta_size, host_code_ptr, host_code_size)) == -EINVAL) {
            printf_log(LOG_NONE, "Failed to lookup address in lookup router: %d\n", ret);
        }
    }
    return ret;
}

int cs2c_calc_sign(const void* guest_code, size_t guest_size, CodeSign* guest_sign)
{
    return cs2s_helper_calc_sign(guest_code, guest_size, guest_sign);
}

const void* cs2c_block_code(const CacheBlockHeader* block)
{
    return cs2s_helper_block_code(block);
}

const void* cs2c_block_meta(const CacheBlockHeader* block)
{
    return cs2s_helper_block_meta(block);
}

int cs2c_for_each_blocks(const char* path, void* data, void (*callback)(void*, const CacheBlockHeader*))
{
    return cs2s_ro_for_each_blocks(cs2s_ro, path, data, callback);
}

void cs2c_exit(void)
{
    cs2s_cmdq_destroy(cs2s_cmdq);
    cs2s_ro_destroy(cs2s_ro);
}
