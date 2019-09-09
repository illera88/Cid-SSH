#ifndef STS_QUEUE_H
#define STS_QUEUE_H

/*
 * Simple thread safe queue (StsQueue) is just an experiment with
 * simulated "namespaces" in C.
 *
 * The idea is simple, just return the functions in a struct.
 * Leak exactly the information that is needed, meaning no special
 * types, structs or other things.
 */

#include "global.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct StsHeader StsHeader;

typedef struct {
    StsHeader* (*const create)();
    void(*const destroy)(StsHeader* handle);
    void(*const push)(StsHeader* handle, void* elem);
    void* (*const pop)(StsHeader* handle);
    void* (*const iterate)();
    void(*const reset)();
    void(*const dump)(StsHeader* handle, void(*cb)(void*));
} _StsQueue;

extern _StsQueue const StsQueue;

#ifdef __cplusplus
}
#endif

#endif