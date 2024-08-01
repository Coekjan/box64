#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "debug.h"
#include "generated/cs2s-ccapi.h"

static CommandQueueClientHandlePtr cs2s_cmdq;
static LookupRouterPtr cs2s_ro;

void cs2c_init(void)
{
    if (cs2s_cmdq_create("develop", &cs2s_cmdq)) {
        printf_log(LOG_NONE, "Failed to create command queue client\n");
        exit(1);
    }
    if (cs2s_cmdq_connect(cs2s_cmdq)) {
        printf_log(LOG_NONE, "Failed to connect to command queue server\n");
        exit(1);
    }
    if (cs2s_ro_create("develop", true, &cs2s_ro)) {
        printf_log(LOG_NONE, "Failed to create lookup router\n");
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
        printf_log(LOG_NONE, "Failed to attach paths to lookup router. Sleep for 1 second and retry\n");
        sleep(1);
    }
}

void cs2c_sync(const char* path, size_t guest_addr, const void* guest_code, size_t guest_code_len, const void* host_code, size_t host_code_len)
{
    int ret;
    if ((ret = cs2s_cmdq_sync(cs2s_cmdq, path, guest_addr, guest_code, guest_code_len, host_code, host_code_len)) != 0) {
        printf_log(LOG_NONE, "Failed to synchronize cache to command queue server: %d\n", ret);
    }
}

int cs2c_lookup(const char* path, size_t guest_addr, const void* guest_code, size_t guest_code_len, void* host_code_buf, size_t host_code_buf_len, size_t* host_code_len)
{
    int ret;
    if ((ret = cs2s_ro_lookup(cs2s_ro, path, guest_addr, guest_code, guest_code_len, host_code_buf, host_code_buf_len, host_code_len)) == -EINVAL) {
        printf_log(LOG_NONE, "Failed to lookup address in lookup router: %d\n", ret);
    }
    return ret;
}

void cs2c_exit(void)
{
    cs2s_cmdq_destroy(cs2s_cmdq);
    cs2s_ro_destroy(cs2s_ro);
}
