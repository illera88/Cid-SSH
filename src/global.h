#pragma once

#ifdef _WIN32
#define _XCLOSESOCKET closesocket
#else /* _WIN32 */
#define _XCLOSESOCKET close
#include <unistd.h>

#ifdef __cplusplus
extern "C"
{
void Sleep(int milliseconds);
}
#endif
#endif
#define CLOSE_SOCKET(s) do { if ((s) != SSH_INVALID_SOCKET) { _XCLOSESOCKET(s); (s) = SSH_INVALID_SOCKET;} } while(0)

#ifdef IS_DEBUG
#define debug printf
#else  
//just doesn't print the printf
#define debug(MESSAGE, ...)
//Unsetting _ssh_log
#define _ssh_log(MESSAGE, ...)
#endif

#ifdef _WIN32
#define pthread_mutex_t CRITICAL_SECTION
#define pthread_mutex_lock EnterCriticalSection
#define pthread_mutex_unlock LeaveCriticalSection
#define pthread_mutex_destroy DeleteCriticalSection
#endif

#ifdef HAVE_PTHREAD
typedef void* thread_rettype_t;
#else
typedef void thread_rettype_t;
#endif
