/* This is a sample implementation of a libssh based SSH server */
/*
Copyright 2003-2009 Aris Adamantiadis
Copyright 2018 T. Wimmer
This file is part of the SSH Library
You are free to copy this file, modify it in any way, consider it being public
domain. This does not apply to the rest of the library though, but it is
allowed to cut-and-paste working code from this file to any license of
program.
The goal is to show the API in action. It's not a reference on how terminal
clients must be made or how a client should react.
*/

/*
 gcc -o sshd_direct-tcpip sshd_direct-tcpip.c -ggdb -Wall `pkg-config libssh --libs --cflags` -I./libssh/include/ -I.
 Example:
  ./sshd_direct-tcpip -v -p 2022 -d serverkey.dsa -r serverkey.rsa 127.0.0.1
*/

#include "socks_proxy.h"
#include "sts_queue.h"
#include "global.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <libssh/channels.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#include <winsock2.h>
#include <process.h>
#include <Windows.h>
#define SEND_FLAGS 0
#else
#include <poll.h>
#include <errno.h>
#define SEND_FLAGS MSG_NOSIGNAL
#endif // _WIN32

void do_cleanup(StsHeader* cleanup_queue) {
    struct event_fd_data_struct* item;
    while ((item = StsQueue.pop(cleanup_queue)) != NULL) {
        _ssh_log(SSH_LOG_PROTOCOL, "=== do_cleanup", "Freeing Channel %d:%d",
            item->channel->local_channel, item->channel->remote_channel);

        if (!ssh_channel_is_closed(item->channel)) {
            ssh_channel_close(item->channel);
        }

        ssh_remove_channel_callbacks(item->channel, item->cb_chan);
        ssh_channel_free(item->channel);


        if (item->fd != SSH_INVALID_SOCKET) {
            _close_socket(*item);
        }

        SAFE_FREE(item->cb_chan);
        SAFE_FREE(item);

        _ssh_log(SSH_LOG_FUNCTIONS, "=== do_cleanup", "Freed.");
    }
}

static int auth_password(ssh_session session, const char* user,
    const char* password, void* userdata) {
    struct thread_info_struct* thread_info = (struct thread_info_struct*)userdata;
    thread_info->authenticated = 1;
    _ssh_log(SSH_LOG_PROTOCOL, "=== auth_password", "Authenticated");
    return SSH_AUTH_SUCCESS;
}


static void stack_socket_close(struct event_fd_data_struct* event_fd_data) {
    if (event_fd_data->stacked != 1 && event_fd_data->thread_info != NULL) {
        _ssh_log(SSH_LOG_FUNCTIONS, "=== stack_socket_close", "Closing fd = %d sockets_cnt = %d", event_fd_data->fd, event_fd_data->thread_info->sockets_cnt);
        event_fd_data->stacked = 1;

        StsQueue.push(event_fd_data->thread_info->cleanup_queue, event_fd_data);
    }
}

static void _close_socket(struct event_fd_data_struct event_fd_data) {
    _ssh_log(SSH_LOG_FUNCTIONS, "=== close_socket", "Closing fd = %d sockets_cnt = %d", event_fd_data.fd, event_fd_data.thread_info->sockets_cnt);
    //ssh_session session = ssh_channel_get_session(event_fd_data.channel);
    //ssh_event_remove_session(mainloop, session);
    ssh_event_remove_fd(event_fd_data.thread_info->event, event_fd_data.fd);
    //ssh_event_add_session(mainloop, session);
    event_fd_data.thread_info->sockets_cnt--;
#ifdef _WIN32
    closesocket(event_fd_data.fd);
#else
    close(event_fd_data.fd);
#endif // _WIN32
    event_fd_data.fd = SSH_INVALID_SOCKET;
}

static void my_channel_wait_close_function(ssh_session session, ssh_channel channel, void* userdata) {
    (void)session;

    struct pending_conn_data_struct* pending_conn_data = (struct pending_conn_data_struct*)userdata;
    _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_WAIT_close_function", "Channel %d:%d closed by remote. State=%d", channel->local_channel, channel->remote_channel, channel->state);

    if (pending_conn_data->event_fd_data != NULL) {
        // We may have dealt with it at my_channel_wait_eof_function
        //stack_socket_close(pending_conn_data->event_fd_data); <<== Dangerous!!
        pending_conn_data->closed = 1;
    }
}

static void my_channel_close_function(ssh_session session, ssh_channel channel, void* userdata) {
    (void)session;

    struct event_fd_data_struct* event_fd_data = (struct event_fd_data_struct*)userdata;
    _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_close_function", "Channel %d:%d closed by remote. State=%d", channel->local_channel, channel->remote_channel, channel->state);

    stack_socket_close(event_fd_data);
}

static void my_channel_wait_eof_function(ssh_session session, ssh_channel channel, void* userdata) {
    (void)session;
    struct pending_conn_data_struct* pending_conn_data = (struct pending_conn_data_struct*)userdata;
    if (pending_conn_data->event_fd_data == NULL) {
        SAFE_FREE(pending_conn_data->buf);
        _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_WAIT_eof_function", "Got EOF on channel %d:%d. Struct is not filled. Weird",
            channel->local_channel, channel->remote_channel);
    }
    else {
        _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_WAIT_eof_function", "Got EOF on channel %d:%d. Shuting down write on socket (fd = %d).",
            channel->local_channel, channel->remote_channel, pending_conn_data->event_fd_data->fd);

        pending_conn_data->closed = 1;
    }
}

static void my_channel_eof_function(ssh_session session, ssh_channel channel, void* userdata) {
    (void)session;
    struct event_fd_data_struct* event_fd_data = (struct event_fd_data_struct*)userdata;
    _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_eof_function", "Got EOF on channel %d:%d. Shuting down write on socket (fd = %d).", channel->local_channel, channel->remote_channel, event_fd_data->fd);

    stack_socket_close(event_fd_data);
}

static void my_channel_exit_status_function(ssh_session session, ssh_channel channel, int exit_status, void* userdata) {
    (void)session;
    struct event_fd_data_struct* event_fd_data = (struct event_fd_data_struct*)userdata;
    _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_exit_status_function", "Got exit status %d on channel %d:%d fd = %d.", exit_status, channel->local_channel, channel->remote_channel, event_fd_data->fd);
}

static int my_channel_data_wait_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata) {
    _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_data_WAIT_function", "Not yet initialized");
    struct pending_conn_data_struct* pending_conn_data = (struct pending_conn_data_struct*)userdata;
    pending_conn_data->buf = malloc(len);
    memcpy(pending_conn_data->buf, data, len);
    pending_conn_data->buflen = len;
    return len;
}

static int my_channel_data_function(ssh_session session, ssh_channel channel, void* data, uint32_t len, int is_stderr, void* userdata) {
    int i = 0;
    struct event_fd_data_struct* event_fd_data = (struct event_fd_data_struct*)userdata;

    if (event_fd_data->channel == NULL) {
        debug("Why we're here? Stacked = %d\n", event_fd_data->stacked);
        return 0;
    }

    _ssh_log(SSH_LOG_PROTOCOL, "=== my_channel_data_function", "%d bytes waiting on channel %d:%d for reading. Fd = %d", len, channel->local_channel, channel->remote_channel, event_fd_data->fd);
    if (len > 0) {
        i = send(event_fd_data->fd, data, len, SEND_FLAGS);
    }
    if (i < 0) {
        _ssh_log(SSH_LOG_WARNING, "=== my_channel_data_function", "Writing to tcp socket %d: %s", event_fd_data->fd, strerror(errno));
        stack_socket_close(event_fd_data);
    }
    else {
        _ssh_log(SSH_LOG_FUNCTIONS, "=== my_channel_data_function", "Sent %d bytes", i);
    }
    return i;
}

static int my_fd_data_function(socket_t fd, int revents, void* userdata) {
    struct event_fd_data_struct* event_fd_data = (struct event_fd_data_struct*)userdata;
    ssh_channel channel = event_fd_data->channel;
    ssh_session session;
    int len, i, wr;
    char buf[16384];
    int	blocking;

    if (channel == NULL) {
        _ssh_log(SSH_LOG_FUNCTIONS, "=== my_fd_data_function", "channel == NULL!");
        return 0;
    }

    session = ssh_channel_get_session(channel);

    if (ssh_channel_is_closed(channel)) {
        _ssh_log(SSH_LOG_FUNCTIONS, "=== my_fd_data_function", "channel is closed!");
        stack_socket_close(event_fd_data);
        return 0;
    }

    if (!(revents & POLLIN)) {
        if (revents & POLLPRI) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== my_fd_data_function", "poll revents & POLLPRI");
        }
        if (revents & POLLOUT) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== my_fd_data_function", "poll revents & POLLOUT");
        }
        if (revents & POLLHUP) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== my_fd_data_function", "poll revents & POLLHUP");
        }
        if (revents & POLLNVAL) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== my_fd_data_function", "poll revents & POLLNVAL");
        }
        if (revents & POLLERR) {
            _ssh_log(SSH_LOG_PROTOCOL, "=== my_fd_data_function", "poll revents & POLLERR");
        }
        //if (revents & POLLRDHUP) {
        //    printf(" POLLRDHUP");
        //}
        return 0;
    }

    blocking = ssh_is_blocking(session);
    ssh_set_blocking(session, 0);

    _ssh_log(SSH_LOG_FUNCTIONS, "=== my_fd_data_function", "Trying to read from tcp socket fd = %d... (Channel %d:%d state=%d)",
        event_fd_data->fd, channel->local_channel, channel->remote_channel, channel->state);
#ifdef _WIN32
    struct sockaddr from;
    int fromlen = sizeof(from);
    len = recvfrom(event_fd_data->fd, buf, sizeof(buf), 0, &from, &fromlen);
#else
    len = recv(event_fd_data->fd, buf, sizeof(buf), 0);
#endif // _WIN32
    if (len < 0) {
        _ssh_log(SSH_LOG_WARNING, "=== my_fd_data_function", "Reading from tcp socket: %s", strerror(errno));

        // ssh_channel_send_eof(channel);
        stack_socket_close(event_fd_data);
    }
    else if (len > 0) {
        if (ssh_channel_is_open(channel)) {
            wr = 0;
            do {
                i = ssh_channel_write(channel, buf, len);
                if (i < 0) {
                    _ssh_log(SSH_LOG_WARNING, "=== my_fd_data_function", "Error writing on the direct-tcpip channel: %d", i);
                    len = wr;
                    break;
                }
                wr += i;
                _ssh_log(SSH_LOG_FUNCTIONS, "=== my_fd_data_function", "channel_write (%d from %d)", wr, len);
            } while (i > 0 && wr < len);
        }
        else {
            _ssh_log(SSH_LOG_WARNING, "=== my_fd_data_function", "Can't write on closed channel!");
        }
    }
    else {
        _ssh_log(SSH_LOG_PROTOCOL, "=== my_fd_data_function", "The destination host has disconnected!");

#ifdef _WIN32
        shutdown(event_fd_data->fd, SD_RECEIVE);
#else
        shutdown(event_fd_data->fd, SHUT_RD);
#endif // _WIN32
        stack_socket_close(event_fd_data);
    }
    ssh_set_blocking(session, blocking);

    return len;
}

static thread_rettype_t connect_thread_worker(void* userdata) {
    struct thread_info_struct* thread_info = (struct thread_info_struct*)userdata;

#ifdef IS_DEBUG
    ssh_set_log_level(SSH_LOG_FUNCTIONS);
#else
    ssh_set_log_level(SSH_LOG_NOLOG);
#endif // DEBUG
   

    while (!thread_info->error) {
        struct pending_conn_data_struct* item;
        while ((item = StsQueue.pop(thread_info->queue)) != NULL) {
            if (item->event_fd_data->fd == SSH_INVALID_SOCKET) {
                item->tries++;
                item->event_fd_data->fd = open_tcp_socket(item->hostname, item->port, item->tries * TIMEOUT, thread_info, NON_BLOCKING);
                if ((item->event_fd_data->fd == SSH_INVALID_SOCKET && item->tries > MAX_TRIES) || item->closed == 1) {
                    if (item->buflen > 0 && item->buf != NULL) {
                        SAFE_FREE(item->buf);
                    }
                    stack_socket_close(item->event_fd_data);
                    continue;
                }

            }
            StsQueue.push(thread_info->queue, item);
#ifdef _WIN32
            Sleep(50);
#else
            usleep(50000);
#endif // _WIN32
        }
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif // _WIN32

        }
#ifdef HAVE_PTHREAD
    return NULL;
#endif
}



void do_set_callbacks(struct thread_info_struct* thread_info) {
    struct pending_conn_data_struct* item;
    int max_in_turn = 10;
    _ssh_log(SSH_LOG_FUNCTIONS, "=== do_set_callbacks", "Running...");

    while ((item = StsQueue.pop(thread_info->queue)) != NULL) {
        if (item->event_fd_data->fd != SSH_INVALID_SOCKET) {
            if (item->event_fd_data->channel == NULL) {
                // client disconnected; channel already closed and freed
                SAFE_FREE(item->event_fd_data->cb_chan);
                item->buflen = 0;
                SAFE_FREE(item->buf);
                // Don't push back
                SAFE_FREE(item);
                continue;
            }
            ssh_remove_channel_callbacks(item->event_fd_data->channel, item->event_fd_data->cb_chan);
            SAFE_FREE(item->event_fd_data->cb_chan);

            if (set_callbacks(item->event_fd_data, thread_info) == -1) {
                // TODO: when failed?
            }

            ssh_set_blocking(thread_info->session, 0);
            my_channel_data_function(thread_info->session, item->event_fd_data->channel, item->buf, item->buflen, 0, item->event_fd_data);
            ssh_set_blocking(thread_info->session, 1);

            item->buflen = 0;
            SAFE_FREE(item->buf);
            SAFE_FREE(item);
        }
        else {
            StsQueue.push(thread_info->queue, item);
            if (--max_in_turn == 0)
                break;
#ifdef _WIN32
            Sleep(5);
#else
            usleep(5000);
#endif // _WIN32        
        }
    }
    // ssh_set_blocking(thread_info->session, 1);
}

// Ret 1 = success 0 = error
static int set_blocking_mode(int socket, int is_blocking)
{
    int ret = 0;
#ifdef WIN32
    /// @note windows sockets are created in blocking mode by default
    // currently on windows, there is no easy way to obtain the socket's current blocking mode since WSAIsBlocking was deprecated
    u_long flags = is_blocking ? 0 : 1;
    ret = NO_ERROR == ioctlsocket(socket, FIONBIO, &flags);
#else
    const int flags = fcntl(socket, F_GETFL, 0);
    if ((flags& O_NONBLOCK) && !is_blocking) { _ssh_log(SSH_LOG_WARNING, "=== set_blocking_mode", "socket was already in non-blocking mode"); return ret; }
    if (!(flags& O_NONBLOCK) && is_blocking) { _ssh_log(SSH_LOG_WARNING, "=== set_blocking_mode", "socket was already in blocking mode"); return ret; }
    ret = 0 == fcntl(socket, F_SETFL, is_blocking ? flags ^ O_NONBLOCK : flags | O_NONBLOCK);
#endif

    return ret;
}

static int do_connect(socket_t s, const char* host, const int port, float timeout) {
    char port_str[15];
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    int ret = -1;

    /*  For some reason when I use this part in Windows, after creating a packet to a non existen IP:port (i.e. 1.2.3.4:443)
        it stops working for the rest good requests that do not timeout. I don't know why that happens.*/
    if (!set_blocking_mode(s, 0)) {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%d", port);

    ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        _ssh_log(SSH_LOG_WARNING, "=== do_connect", "Couldn't get address info. Err %d", ret);
        goto end;
    }

#ifdef _WIN32
    if (connect(s, result->ai_addr, result->ai_addrlen) != -1) {
        freeaddrinfo(result);
        goto end;
    }

    // windows behaviour is different than Linux and there is more to do because WSAEWOULDBLOCK does not mean error really
    ret = WSAGetLastError();

    if (ret != WSAEWOULDBLOCK) {
        goto end;
    }
#else
    ret = connect(s, result->ai_addr, result->ai_addrlen);
    if (ret == -1 && errno != EINPROGRESS) {
        goto end;
    }
#endif // _WIN32

    freeaddrinfo(result);

    fd_set Write, Err;
    FD_ZERO(&Write);
    FD_ZERO(&Err);
    FD_SET(s, &Write);
    FD_SET(s, &Err);

    struct timeval Timeout;
    Timeout.tv_sec = (long)timeout;
    Timeout.tv_usec = (long)((timeout - Timeout.tv_sec) * 1000000);

#ifdef _WIN32
    ret = select(0, NULL, &Write, &Err, &Timeout);
    if (ret == SOCKET_ERROR) {
        ret = WSAGetLastError();
        goto end;
    }

    if (ret == 0) { //timeout
        debug("Socket %d Timeout %ld' %ld''\n", s, Timeout.tv_sec, Timeout.tv_usec);
        ret = WSAETIMEDOUT;
        goto end;
    }

    if (FD_ISSET(s, &Write)) { //connected
        ret = 0;
        goto end;
    }

    if (FD_ISSET(s, &Err)) { //error
        u_long err;
        socklen_t err_len = sizeof(err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)& err, &err_len) == SOCKET_ERROR) {
            ret = WSAGetLastError();
        }
        ret = (int)err;
        goto end;
    }
#else
    ret = select(s + 1, NULL, &Write, &Err, &Timeout);
    if (ret < 0) {
        _ssh_log(SSH_LOG_WARNING, "=== do_connect", "select: %s", strerror(errno));
        goto end;
    }
    else if (ret == 0) { //timeout
        _ssh_log(SSH_LOG_PROTOCOL, "=== do_connect", "Socket %d Timeout %ld' %ld''", s, Timeout.tv_sec, Timeout.tv_usec);
        ret = -1;
        goto end;
    }

    if (FD_ISSET(s, &Write)) { //connected
        ret = 0;
        goto end;
    }

    if (FD_ISSET(s, &Err)) { //error
        u_long err;
        socklen_t err_len = sizeof(err);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &err_len) == -1) {
            _ssh_log(SSH_LOG_WARNING, "=== do_connect", "Error from scoket %d: %lu", s, err);
        }
        goto end;
    }
#endif // _WIN32

end:
    if (!set_blocking_mode(s, 1)) {
        return -1;
    }
    return ret;
}

static int do_connect_blocking(socket_t s, const char* dest_hostname, int dest_port, float timeout) {
    struct timeval tv;
    char port_str[15];
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    int ret = -1;
    tv.tv_sec = (long)timeout;
    tv.tv_usec = (long)((timeout - tv.tv_sec) * 1000000);

    if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)& tv, sizeof(tv)) < 0) {
        _ssh_log(SSH_LOG_WARNING, "=== do_connect_blocking", "setsockopt failed");
        return -1;
    }

    if (setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)& tv, sizeof(tv)) < 0) {
        _ssh_log(SSH_LOG_WARNING, "=== do_connect_blocking", "setsockopt failed");
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    snprintf(port_str, sizeof(port_str), "%d", dest_port);

    ret = getaddrinfo(dest_hostname, port_str, &hints, &result);
    if (ret != 0) {
        _ssh_log(SSH_LOG_WARNING, "=== do_connect_blocking", "Couldn't get address info. Err %d", ret);
        return -1;
    }

    if (connect(s, result->ai_addr, result->ai_addrlen) != -1) {
        _ssh_log(SSH_LOG_WARNING, "=== do_connect_blocking", "ERROR connecting: %s", strerror(errno));
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    return 0;
}

static socket_t open_tcp_socket(const char* dest_hostname, int dest_port,
    float timeout, struct thread_info_struct * thread_info, int no_blocking) {
    int rc;
    socket_t forwardsock = SSH_INVALID_SOCKET;

    _ssh_log(SSH_LOG_PROTOCOL, "=== open_tcp_socket", "Connecting to %s on port %d", dest_hostname, dest_port);

    forwardsock = socket(AF_INET, SOCK_STREAM, 0);
    if (forwardsock < 0) {
        _ssh_log(SSH_LOG_WARNING, "=== open_tcp_socket", "ERROR opening socket: %s", strerror(errno));
        return SSH_INVALID_SOCKET;
    }

    if (no_blocking != 0) {
        rc = do_connect(forwardsock, dest_hostname, dest_port, timeout);
    }
    else {
        rc = do_connect_blocking(forwardsock, dest_hostname, dest_port, timeout);
    }

    if (rc != 0) {
#ifdef _WIN32
        closesocket(forwardsock);
#else
        close(forwardsock);
#endif // _WIN32	
        _ssh_log(SSH_LOG_WARNING, "=== open_tcp_socket", "ERROR timing out connecting: %s. ", strerror(errno));
        return SSH_INVALID_SOCKET;
    }

    thread_info->sockets_cnt++;
    _ssh_log(SSH_LOG_FUNCTIONS, "=== open_tcp_socket", "Connected. sockets_cnt = %d. socket # %d", thread_info->sockets_cnt, forwardsock);

    return forwardsock;
}

/* Call this function when the connection of Fd is established*/
static int set_callbacks(struct event_fd_data_struct * event_fd_data, struct thread_info_struct * thread_info) {
    struct ssh_channel_callbacks_struct* cb_chan;
    _ssh_log(SSH_LOG_FUNCTIONS, "=== set_callbacks", "SET for sock %d, Thread %p", event_fd_data->fd, thread_info);

    cb_chan = malloc(sizeof (*cb_chan));
    memset(cb_chan, '\x00', sizeof (*cb_chan));
    ssh_callbacks_init(cb_chan);
    cb_chan->userdata = event_fd_data;
    cb_chan->channel_eof_function = my_channel_eof_function;
    cb_chan->channel_close_function = my_channel_close_function;
    cb_chan->channel_data_function = my_channel_data_function;
    cb_chan->channel_exit_status_function = my_channel_exit_status_function;

    event_fd_data->cb_chan = cb_chan;

    if (ssh_set_channel_callbacks(event_fd_data->channel, event_fd_data->cb_chan) != SSH_OK) {
        _ssh_log(SSH_LOG_FUNCTIONS, "=== set_callbacks", "ERROR ssh_set_channel_callbacks failed for sock %d, Thread %p", event_fd_data->fd, thread_info);
        return -1;
    }

    if (ssh_event_add_fd(thread_info->event, event_fd_data->fd, POLLIN, my_fd_data_function, event_fd_data) != SSH_OK) {
        _ssh_log(SSH_LOG_FUNCTIONS, "=== set_callbacks", "ERROR ssh_event_add_fd failed for sock %d, Thread %p", event_fd_data->fd, thread_info);
        return -1;
    }

    _ssh_log(SSH_LOG_FUNCTIONS, "=== set_callbacks", "ENDED for sock %d, Thread %p", event_fd_data->fd, thread_info);
    return 0;
}


int handle_socks_connection(ssh_message message, struct thread_info_struct* thread_info) {
    //ssh_message_get(session);
    ssh_channel channel;
    struct ssh_channel_callbacks_struct* cb_chan;
    struct event_fd_data_struct* event_fd_data;
    struct pending_conn_data_struct* incomming_request;


    /* We first create the objects and threads needed for dynamic port forwarding*/
    thread_info->queue = StsQueue.create();

#ifdef HAVE_PTHREAD
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, connect_thread_worker, thread_info);
    if (rc != 0) {
        _ssh_log(SSH_LOG_WARNING, "=== auth_password", "Error starting thread: %d", rc);
        return 1;
    }
#else
    HANDLE thread = (HANDLE)_beginthread(connect_thread_worker, 0, thread_info);
#endif // HAVE_PTHREAD

    thread_info->connection_thread = thread;
    thread_info->dynamic_port_fwr = 1;


    channel = ssh_message_channel_request_open_reply_accept(message);

    if (channel == NULL) {
        _ssh_log(SSH_LOG_WARNING, "=== message_callback", "Accepting direct-tcpip channel failed!");
        return 1;
    }
    else {
        _ssh_log(SSH_LOG_PROTOCOL, "=== message_callback", "Connected to channel!");


        const char* dest_hostname = ssh_message_channel_request_open_destination(message);
        int dest_port = ssh_message_channel_request_open_destination_port(message);

        event_fd_data = malloc(sizeof * event_fd_data);
        memset(event_fd_data, '\x00', sizeof *event_fd_data);

        cb_chan = malloc(sizeof * cb_chan);
        memset(cb_chan, '\x00', sizeof * cb_chan);
        incomming_request = malloc(sizeof * incomming_request);
        memset(incomming_request, '\x00', sizeof * incomming_request);

        event_fd_data->channel = channel;
        event_fd_data->fd = SSH_INVALID_SOCKET;
        event_fd_data->thread_info = thread_info;
        event_fd_data->stacked = 0;
        event_fd_data->cb_chan = cb_chan;

        cb_chan->userdata = incomming_request;
        cb_chan->channel_data_function = my_channel_data_wait_function;
        cb_chan->channel_close_function = my_channel_wait_close_function;
        cb_chan->channel_eof_function = my_channel_wait_eof_function;

        incomming_request->event_fd_data = event_fd_data;
        incomming_request->tries = 0;
        incomming_request->closed = 0;
        incomming_request->port = dest_port;
        incomming_request->hostname[0] = '\0';
        strncpy(incomming_request->hostname, dest_hostname, MAX_HOSTNAME_LEN);
        incomming_request->buf = NULL;
        incomming_request->buflen = 0;

        StsQueue.push(thread_info->queue, incomming_request);


        ssh_callbacks_init(cb_chan);
        if (ssh_set_channel_callbacks(channel, cb_chan) != SSH_OK) {
            _ssh_log(SSH_LOG_FUNCTIONS, "=== message_callback", "ERROR ssh_set_channel_callbacks failed");
            return 1;
        }

        _ssh_log(SSH_LOG_PROTOCOL, "=== message_callback", "Added %s:%d to connecting queue", dest_hostname, dest_port);

        return 0;
    }
}