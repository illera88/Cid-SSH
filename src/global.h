#pragma once

#ifdef _WIN32
#define _XCLOSESOCKET closesocket
#else /* _WIN32 */
#define _XCLOSESOCKET close
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

