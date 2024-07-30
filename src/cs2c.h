#ifndef CS2C_H
#define CS2C_H

#include "generated/cs2s-ccapi.h"

void cs2c_init(void);
void cs2c_lib_attach(const char *const *libraries, size_t libraries_len);
void cs2c_sync(const char* library, size_t guest_addr, const void* guest_code, size_t guest_code_len, const void* host_code, size_t host_code_len);
int cs2c_lookup(const char* library, size_t guest_addr, const void* guest_code, size_t guest_code_len, void* host_code_buf, size_t host_code_buf_len, size_t* host_code_len);
void cs2c_exit(void);

#endif
