#pragma once

#ifdef IS_DEBUG
#define debug printf
#else  
//just doesn't print the printf
#define debug(MESSAGE, ...)
//Unsetting _ssh_log
#define _ssh_log(MESSAGE, ...)
#endif

