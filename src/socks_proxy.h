#pragma once


#include <libssh/libssh.h>
#include <config.h>

#include "sts_queue.h"
#include "global.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>
typedef void* thread_rettype_t;
#else
typedef void thread_rettype_t;
#endif

#define MAX_TRIES 3
#define TIMEOUT 0.5f // in seconds
#ifndef MAX_HOSTNAME_LEN
#define MAX_HOSTNAME_LEN 128
#endif // !MAX_HOSTNAME_LEN

#define NON_BLOCKING 1

#ifdef __cplusplus
extern "C"
{
#endif


struct thread_info_struct {
    ssh_channel channel;
    ssh_session session;
    ssh_event event;
    StsHeader* queue;
    int authenticated;
    int error;
    int sockets_cnt;
    StsHeader* cleanup_queue;
    int dynamic_port_fwr; // This flag will be set if -D is used
    pthread_mutex_t mutex;
#ifdef _WIN32
    HANDLE connection_thread;
    HANDLE shell_thread;
    HPCON pty_handle;
#else
    pthread_t connection_thread;
    pthread_t shell_thread;
#endif
    COORD win_size;
};


struct event_fd_data_struct {
    socket_t fd;
    ssh_channel channel;
    struct ssh_channel_callbacks_struct* cb_chan;
    int stacked;
    struct thread_info_struct* thread_info;
};


struct pending_conn_data_struct {
    int port;
    char hostname[MAX_HOSTNAME_LEN];
    int tries;
    int closed;
    struct event_fd_data_struct* event_fd_data;
    void* buf;
    int buflen;
};



static void _close_socket(struct event_fd_data_struct event_fd_data);
static socket_t open_tcp_socket(const char* dest_hostname, int dest_port, float timeout, struct thread_info_struct* thread_info, int no_blocking);
static int set_callbacks(struct event_fd_data_struct* event_fd_data, struct thread_info_struct* thread_info);

void _close_socket(struct event_fd_data_struct event_fd_data);

static thread_rettype_t connect_thread_worker(void* userdata);

int handle_socks_connection(ssh_message message, struct thread_info_struct* thread_info);

static int set_callbacks(struct event_fd_data_struct* event_fd_data, struct thread_info_struct* thread_info);

static socket_t open_tcp_socket(const char* dest_hostname, int dest_port,
    float timeout, struct thread_info_struct* thread_info, int no_blocking);

static int do_connect_blocking(socket_t s, const char* dest_hostname, int dest_port, float timeout);
static int do_connect(socket_t s, const char* host, const int port, float timeout);
static int set_blocking_mode(int socket, int is_blocking);

static int my_fd_data_function(socket_t fd, int revents, void* userdata);
static int my_channel_data_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata);
static int my_channel_data_wait_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata);
static void my_channel_exit_status_function(ssh_session session, ssh_channel channel, int exit_status, void* userdata);

static void my_channel_eof_function(ssh_session session, ssh_channel channel, void* userdata);

static void my_channel_wait_eof_function(ssh_session session, ssh_channel channel, void* userdata);


void do_cleanup(StsHeader* cleanup_queue);
void do_set_callbacks(struct thread_info_struct* thread_info);

static int auth_password(ssh_session session, const char* user,
    const char* password, void* userdata);

#ifdef __cplusplus
}
#endif