/*******************************************************************
 * File automatically generated by rebuild_wrappers.py (v2.5.0.24) *
 *******************************************************************/
#ifndef __wrappednspr4TYPES_H_
#define __wrappednspr4TYPES_H_

#ifndef LIBNAME
#error You should only #include this file inside a wrapped*.c file
#endif
#ifndef ADDED_FUNCTIONS
#define ADDED_FUNCTIONS() 
#endif

typedef int32_t (*iFpp_t)(void*, void*);
typedef int32_t (*iFppp_t)(void*, void*, void*);

#define SUPER() ADDED_FUNCTIONS() \
	GO(PR_CallOnce, iFpp_t) \
	GO(PR_CallOnceWithArg, iFppp_t)

#endif // __wrappednspr4TYPES_H_
