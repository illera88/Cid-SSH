#pragma once

#include <config.h>

#include <libssh/libssh.h>

#include "sts_queue.h"

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
    struct cleanup_node_struct* cleanup_stack;
};

struct event_fd_data_struct {
    socket_t fd;
    ssh_channel channel;
    struct ssh_channel_callbacks_struct* cb_chan;
    int stacked;
    struct thread_info_struct* thread_info;
};

struct cleanup_node_struct {
    struct event_fd_data_struct* data;
    struct cleanup_node_struct* next;
};

struct pending_conn_data_struct {
    //socket_t fd;
    //ssh_channel channel;
    //ssh_session session;
    int port;
    char hostname[MAX_HOSTNAME_LEN];
    int tries;
    int closed;
    struct event_fd_data_struct* event_fd_data;
    void* buf;
    int buflen;
};



thread_rettype_t connect_thread_worker(void* userdata);

int handle_socks_connection(ssh_message message, struct thread_info_struct* thread_info);

static int set_callbacks(struct event_fd_data_struct* event_fd_data, struct thread_info_struct* thread_info);

static socket_t open_tcp_socket(const char* dest_hostname, int dest_port,
    float timeout, struct thread_info_struct* thread_info, int no_blocking);

static int do_connect_blocking(socket_t s, const char* dest_hostname, int dest_port, float timeout);
static int do_connect(socket_t s, const char* host, const int port, float timeout);
static int set_blocking_mode(int socket, int is_blocking);

//static thread_rettype_t connect_thread_worker(void* userdata);
static int my_fd_data_function(socket_t fd, int revents, void* userdata);
static int my_channel_data_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata);
static int my_channel_data_wait_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata);
static void my_channel_exit_status_function(ssh_session session, ssh_channel channel, int exit_status, void* userdata);

static void my_channel_eof_function(ssh_session session, ssh_channel channel, void* userdata);

static void my_channel_wait_eof_function(ssh_session session, ssh_channel channel, void* userdata);



void do_cleanup(struct cleanup_node_struct** head_ref);
void do_set_callbacks(struct thread_info_struct* thread_info);


void global_request(ssh_session session, ssh_message message, void* userdata);

static int auth_password(ssh_session session, const char* user,
    const char* password, void* userdata);

#ifdef WITH_GSSAPI
static int auth_gssapi_mic(ssh_session session, const char* user, const char* principal, void* userdata);
#endif

static int subsystem_request(ssh_session session, ssh_channel channel, const char* subsystem, void* userdata);
ssh_channel new_session_channel(ssh_session session, void* userdata);
int service_request(ssh_session session, const char* service, void* userdata);

#ifdef __cplusplus
}
#endif