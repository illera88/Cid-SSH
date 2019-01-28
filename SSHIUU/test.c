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

#define LIBSSH_STATIC 1
#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
//#include <libssh/messages.h>
#include <libssh/channels.h>
#include <libssh/poll.h>


#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/etc/ssh/"
#endif
#endif

#define USER "myuser"
#define PASSWORD "mypassword"

static int authenticated = 0;
static int tries = 0;
static int error = 0;
//static ssh_channel chan=NULL;
static ssh_event mainloop = NULL;


static int auth_password(ssh_session session, const char *user,
	const char *password, void *userdata) {
	authenticated = 1;
	printf("Authenticating user %s pwd %s\n", user, password);
	return SSH_AUTH_SUCCESS;
}


static void my_channel_close_function(ssh_session session, ssh_channel channel, void *userdata) {
	(void)session;
	(void)userdata;
#ifdef _WIN32
	SOCKET fd = *((SOCKET *)userdata);
#else
	int fd = *((int *)userdata);
#endif

	printf("Channel %d:%d closed by remote. State=%d\n", channel->local_channel, channel->remote_channel, channel->state);
	// Done by lib
	/*if(ssh_channel_is_open(channel)) {
		ssh_channel_close(channel);
		printf("Closing channel\n");
	}*/

#ifdef _WIN32
	closesocket(fd);
#else
	close(fd);
#endif

}

static void my_channel_eof_function(ssh_session session, ssh_channel channel, void *userdata) {
	(void)session;
	//(void)userdata;
	int fd = *((int *)userdata);
	printf("Got EOF on channel %d:%d. Shuting down write on socket (fd = %d).\n", channel->local_channel, channel->remote_channel, fd);
	//ssh_event_remove_fd(mainloop, fd);

#ifdef _WIN32
	if (-1 == shutdown(fd, SD_SEND)) {
#elif
	if (-1 == shutdown(fd, SHUT_WR)) {
#endif // DEBUG	
		perror("Shutdown socket for writing");
	}
	}

static int my_channel_data_function(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata) {
	int i = 0;
	int fd = *((int *)userdata);

	printf("%d bytes waiting on channel %d:%d for reading. Fd = %d\n", len, channel->local_channel, channel->remote_channel, fd);
	if (len > 0) {
		i = send(fd, data, len, 0);
	}
	if (i < 0) {
#ifdef _WIN32
		int err = WSAGetLastError();
		switch (err)
		{
		case WSAECONNABORTED:
			printf("Software caused connection abort.\
				An established connection was aborted by the software in your host computer, possibly due to a data transmission time - out or protocol error.\n");
			break;
		default:
			break;
		}
		printf("Error Reading from tcp socket. Error %d\n", err);

		ssh_event_remove_fd(mainloop, fd);
		closesocket(fd);
#else
		perror("Error writting from tcp socket: ");
		ssh_event_remove_fd(mainloop, fd);
		close(fd);
#endif	

		ssh_channel_send_eof(channel);
	}
	else {
		printf("Sent %d bytes\n", i);
	}
	return i;
}

static int cb_readsock(socket_t fd, int revents, void *userdata) {
	ssh_channel channel = (ssh_channel)userdata;
	ssh_session session;
	int len, i, wr;
	char buf[16384];
	int	blocking;

	if (channel == NULL) {
		fprintf(stderr, "channel == NULL!\n");
	}

	session = ssh_channel_get_session(channel);

	blocking = ssh_is_blocking(session);
	ssh_set_blocking(session, 0);

	printf("Trying to read from tcp socket fd = %d... (Channel %d:%d state=%d)\n", fd, channel->local_channel, channel->remote_channel, channel->state);

	// ToDo: what if read data is > 16384 ??
#ifdef _WIN32
	struct sockaddr from;
	int fromlen = sizeof(from);
	len = recvfrom(fd, buf, sizeof(buf), 0, &from, &fromlen);
#else
	len = recv(fd, buf, sizeof(buf), 0);
#endif // _WIN32

	if (len < 0) {
#ifdef _WIN32
		printf("Error Reading from tcp socket. Error %d\n", WSAGetLastError());

		ssh_event_remove_fd(mainloop, fd);
		closesocket(fd);
#else
		perror("Error Reading from tcp socket: ");
		ssh_event_remove_fd(mainloop, fd);
		close(fd);
#endif		
		ssh_channel_send_eof(channel);
	}
	else if (len > 0) {
		if (ssh_channel_is_open(channel)) {
			wr = 0;
			do {
				printf("channel_write (wr=%d)\n", wr);
				i = ssh_channel_write(channel, buf, len);
				if (i < 0) {
					fprintf(stderr, "Error writing on the direct-tcpip channel: %d\n", i);
					len = wr;
					break;
				}
				wr += i;
			} while (i > 0 && wr < len);
		}
		else {
			fprintf(stderr, "Can't write on closed channel!\n");
		}
	}
	else {
		printf("The destination host has disconnected!\n");
		ssh_event_remove_fd(mainloop, fd);
#ifdef _WIN32
		shutdown(fd, SD_RECEIVE);
#elif
		shutdown(fd, SHUT_RD);
#endif // _WIN32

		if (ssh_channel_is_open(channel))
			ssh_channel_close(channel);
	}
	ssh_set_blocking(session, blocking);

	return len;
}

#ifdef _WIN32
SOCKET open_tcp_socket(ssh_message msg) {
	struct sockaddr_in sin;
	SOCKET forwardsock = 0;
#else
int open_tcp_socket(ssh_message msg) {
	struct sockaddr_in sin;
	int forwardsock = -1;
#endif

	struct hostent *host;
	const char *dest_hostname;
	int dest_port;

	forwardsock = socket(AF_INET, SOCK_STREAM, 0);

	if (forwardsock < 0) {
		perror("ERROR opening socket");
		return -1;
	}

	dest_hostname = ssh_message_channel_request_open_destination(msg);
	dest_port = ssh_message_channel_request_open_destination_port(msg);

	printf("Connecting to %s on port %d\n", dest_hostname, dest_port);

	host = gethostbyname(dest_hostname);
	if (host == NULL) {
		fprintf(stderr, "ERROR, no such host: %s\n", dest_hostname);
		return -1;
	}

	memset((char *)&sin, '\0', sizeof(sin));
	sin.sin_family = AF_INET;
	memcpy((char *)&sin.sin_addr.s_addr, (char *)host->h_addr, host->h_length);
	sin.sin_port = htons(dest_port);

	if (connect(forwardsock, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("ERROR connecting");
		return -1;
	}

	printf("Connected.\n");
	return forwardsock;
}


static int message_callback(ssh_session session, ssh_message message, void *userdata) {
	(void)session;
	(void)message;
	(void)userdata;
	ssh_channel channel;
#ifdef _WIN32
	SOCKET *pFd;
#else
	int *pFd;
#endif

	struct ssh_channel_callbacks_struct *cb_chan;

	//int dest_port;
	auto type = ssh_message_type(message);
	auto subtype = ssh_message_subtype(message);
	printf("Message type: %d\n", type);
	printf("Message Subtype: %d\n", subtype);
	if (type == SSH_REQUEST_CHANNEL_OPEN) {
		//printf("channel_request_open.sender: %d\n", message->channel_request_open.sender);
		printf("channel_request_open\n");

		if (subtype == SSH_CHANNEL_DIRECT_TCPIP) {
			channel = ssh_message_channel_request_open_reply_accept(message);

			//	return 0;
			if (channel == NULL) {
				printf("Accepting direct-tcpip channel failed!\n");
				return 1;
			}
			else {
				printf("Connected to channel!\n");
				pFd = malloc(sizeof(int));
				cb_chan = malloc(sizeof(struct ssh_channel_callbacks_struct));

				*pFd = open_tcp_socket(message);
				if (-1 == *pFd) {
					return 1;
				}

				cb_chan->userdata = pFd;
				cb_chan->channel_eof_function = my_channel_eof_function;
				cb_chan->channel_close_function = my_channel_close_function;
				cb_chan->channel_data_function = my_channel_data_function;

				ssh_callbacks_init(cb_chan);
				ssh_set_channel_callbacks(channel, cb_chan);

				ssh_event_add_fd(mainloop, (socket_t)*pFd, POLLIN, cb_readsock, channel);

				return 0;
			}
		}
	}

	else if (subtype == SSH_CHANNEL_REQUEST_SHELL) {
		printf("Requesting shell\n");
		// Call SSHServer::main_loop(channel); in a new thread


	}

	return 1;
}

int main2(int argc, char **argv) {
	ssh_session session;
	ssh_bind sshbind;
	struct ssh_server_callbacks_struct cb = {
		.userdata = NULL,
		.auth_password_function = auth_password,
	};

	int ret;

	ssh_init();

	sshbind = ssh_bind_new();
	session = ssh_new();
	mainloop = ssh_event_new();

	int port = 2222;
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "C:\\Users\\alberto.garcia\\Downloads\\keys\\ssh_host_dsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "C:\\Users\\alberto.garcia\\Downloads\\keys\\ssh_host_rsa_key");
	ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);


	(void)argc;
	(void)argv;

	if (ssh_bind_listen(sshbind) < 0) {
		printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
		return 1;
	}

	if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
		printf("error accepting a connection : %s\n", ssh_get_error(sshbind));
		ret = 1;
		goto shutdown;
	}

	ssh_callbacks_init(&cb);
	ssh_set_server_callbacks(session, &cb);

	ssh_set_message_callback(session, message_callback, (void *)NULL);

	if (ssh_handle_key_exchange(session)) {
		printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
		ret = 1;
		goto shutdown;
	}
	ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
	ssh_event_add_session(mainloop, session);

	while (!authenticated) {
		if (error)
			break;
		if (ssh_event_dopoll(mainloop, -1) == SSH_ERROR) {
			printf("Error : %s\n", ssh_get_error(session));
			ret = 1;
			goto shutdown;
		}
	}
	if (error) {
		printf("Error, exiting loop\n");
	}
	else {
		printf("Authenticated and got a channel\n");

		while (!error) {
			if (ssh_event_dopoll(mainloop, 100) == SSH_ERROR) {
				printf("Error : %s\n", ssh_get_error(session));
				ret = 1;
				goto shutdown;
			}
		}
	}

shutdown:
	ssh_disconnect(session);
	ssh_bind_free(sshbind);
	ssh_finalize();
	return ret;
}
