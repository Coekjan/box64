/*******************************************************************
 * File automatically generated by rebuild_wrappers.py (v2.5.0.24) *
 *******************************************************************/
#ifndef __wrappedtcmallocminimalTYPES_H_
#define __wrappedtcmallocminimalTYPES_H_

#ifndef LIBNAME
#error You should only #include this file inside a wrapped*.c file
#endif
#ifndef ADDED_FUNCTIONS
#define ADDED_FUNCTIONS() 
#endif

typedef void* (*pFp_t)(void*);
typedef int32_t (*iFpL_t)(void*, uintptr_t);
typedef void* (*pFpLiiil_t)(void*, uintptr_t, int32_t, int32_t, int32_t, intptr_t);

#define SUPER() ADDED_FUNCTIONS() \
	GO(mallinfo, pFp_t) \
	GO(munmap, iFpL_t) \
	GO(mmap, pFpLiiil_t) \
	GO(mmap64, pFpLiiil_t)

#endif // __wrappedtcmallocminimalTYPES_H_
