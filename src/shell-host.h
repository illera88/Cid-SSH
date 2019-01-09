#pragma once

#include<Windows.h>
struct thread_args {
    HANDLE pipe_in;
    HANDLE pipe_out;
    HANDLE pipe_ctrl;
    HANDLE child;
    HANDLE monitor_thread;
    HANDLE io_thread;
    HANDLE ux_thread;
    HANDLE ctrl_thread;
    DWORD hostProcessId;
    DWORD hostThreadId;
    DWORD childProcessId;
    HANDLE child_out;
    HANDLE child_in;
    HANDLE child_err;
};

#ifdef __cplusplus
extern "C"
#endif
int start_with_pty(struct thread_args* args);
