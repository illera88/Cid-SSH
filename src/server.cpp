#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <thread>

#include "server.h"

// to generate RSA keys
#include <openssl/pem.h>

std::string SSHServer::priv_key;
const char* SSHServer::ip="127.0.0.1";

SSHServer::SSHServer()
{
    if (gen_rsa_keys()) {
        printf("[+] RSA keys generated correctly\n");
    }
    else {
        printf("[+] Error generating RSA keys\n");
    }
}

#ifdef _WIN32
int SSHServer::copy_fd_to_chan_win(ssh_channel chan, void *userdata) {
    char buf[2048];
    int sz = 0;

    if (!chan) {
        struct data_arg my_data = *(struct data_arg*)userdata;
        CloseHandle(my_data.g_hChildStd_IN_Wr);

        return -1;
    }
    
    struct data_arg my_data = *(struct data_arg*)userdata;
    DWORD n_to_read;
    PeekNamedPipe(my_data.g_hChildStd_OUT_Rd, NULL, NULL, NULL, &n_to_read, NULL);

    if (n_to_read == 0)
        return 0;

    DWORD dwRead = 0;
    bool SUCCESS = ReadFile(my_data.g_hChildStd_OUT_Rd, buf, 2048, &dwRead, NULL);
    printf("Error %d\n", GetLastError());
    sz = (int)dwRead;

    if (sz > 0) {
        ssh_channel_write(chan, buf, sz);
    }
  
    return sz;
}

#else
int SSHServer::copy_fd_to_chan(socket_t fd, int revents, void *userdata) {
    ssh_channel chan = (ssh_channel)userdata;
    char buf[2048];
    int sz = 0;

    if (!chan) {
        close(fd);
        return -1;
    }
    if (revents & POLLIN) {
        sz = read(fd, buf, 2048);

        if (sz > 0) {
            ssh_channel_write(chan, buf, sz);
        }
    }
    if (revents & POLLHUP) {
        ssh_channel_close(chan);
        sz = -1;
    }
    return sz;
}
#endif

int SSHServer::copy_chan_to_fd(ssh_session session,
    ssh_channel channel,
    void *data,
    uint32_t len,
    int is_stderr,
    void *userdata) {    
    int sz;
    (void)session;
    (void)channel;
    (void)is_stderr;

    
#ifdef _WIN32
    struct data_arg my_data = *(struct data_arg*)userdata;
    DWORD dwWritten = 0;
    BOOL SUCCESS = WriteFile(my_data.g_hChildStd_IN_Wr, data, len, &dwWritten, NULL);
    sz = (int)dwWritten;
#else
    int fd = *(int*)userdata;
    sz = write(fd, data, len);
#endif // _WIN32

    
    return sz;
}

void SSHServer::chan_close(ssh_session session, ssh_channel channel, void *userdata) {
#ifdef _WIN32
    struct data_arg my_data = *(struct data_arg*)userdata;
    CloseHandle(my_data.g_hChildStd_IN_Wr);
#else
    int fd = *(int*)userdata;
#endif // _WIN32

    (void)session;
    (void)channel;  
}

bool SSHServer::gen_rsa_keys() {
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    EVP_PKEY        *key = NULL;
    BIO             *bio = NULL;
    int             bits = 2048;
    unsigned long   e = RSA_F4;
    char            *pem_key = nullptr;
    int keylen;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1) {
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        goto free_all;
    }

    key = EVP_PKEY_new();
    if (!EVP_PKEY_set1_RSA(key, r)) {
        goto free_all;
    }
    bio = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPrivateKey(bio, r, NULL, NULL, 0, NULL, NULL);
    keylen = BIO_pending(bio);
    pem_key = (char*)calloc(keylen + 1, 1); /* Null-terminate */
    BIO_read(bio, pem_key, keylen);
    priv_key = std::string(pem_key);

free_all:
    if (pem_key != nullptr)free(pem_key);
    BIO_free(bio);
    EVP_PKEY_free(key);

    RSA_free(r);
    BN_free(bne);

    return ret == 1;
}

int SSHServer::auth_password(const char *user, const char *password) {
    if (strcmp(user, "alberto.garcia"))
        return 0;
    if (strcmp(password, "123abc."))
        return 0;
    return 1; // authenticated
}

int SSHServer::authenticate(ssh_session session) {
    ssh_message message;

    do {
        message = ssh_message_get(session);
        if (!message)
            break;
        switch (ssh_message_type(message)) {
        case SSH_REQUEST_AUTH:
            switch (ssh_message_subtype(message)) {
            case SSH_AUTH_METHOD_PASSWORD:
                printf("User %s wants to auth with pass %s\n",
                    ssh_message_auth_user(message),
                    ssh_message_auth_password(message));
                if (auth_password(ssh_message_auth_user(message),
                    ssh_message_auth_password(message))) {
                    ssh_message_auth_reply_success(message, 0);
                    ssh_message_free(message);
                    return 1;
                }
                ssh_message_auth_set_methods(message,
                    SSH_AUTH_METHOD_PASSWORD |
                    SSH_AUTH_METHOD_INTERACTIVE);
                // not authenticated, send default message
                ssh_message_reply_default(message);
                break;

            case SSH_AUTH_METHOD_NONE:
            default:
                printf("User %s wants to auth with unknown auth %d\n",
                    ssh_message_auth_user(message),
                    ssh_message_subtype(message));
                ssh_message_auth_set_methods(message,
                    SSH_AUTH_METHOD_PASSWORD |
                    SSH_AUTH_METHOD_INTERACTIVE);
                ssh_message_reply_default(message);
                break;
            }
            break;
        default:
            ssh_message_auth_set_methods(message,
                SSH_AUTH_METHOD_PASSWORD |
                SSH_AUTH_METHOD_INTERACTIVE);
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (1);
    return 0;
}

int SSHServer::main_loop(ssh_channel chan) {
    ssh_session session = ssh_channel_get_session(chan);
    socket_t fd = 1;
    struct termios *term = NULL;
    struct winsize *win = NULL;
#ifndef _WIN32
    pid_t childpid;
#endif
    ssh_event event;
    
    struct ssh_channel_callbacks_struct cb;
    cb.channel_data_function = SSHServer::copy_chan_to_fd;
    cb.channel_eof_function = SSHServer::chan_close;
    cb.channel_close_function = SSHServer::chan_close;
    cb.userdata = NULL;

#ifdef _WIN32
    HANDLE g_hChildStd_IN_Rd = NULL;
    HANDLE g_hChildStd_IN_Wr = NULL;
    HANDLE g_hChildStd_OUT_Rd = NULL;
    HANDLE g_hChildStd_OUT_Wr = NULL;
    SECURITY_ATTRIBUTES saAttr;

    // Set the bInheritHandle flag so pipe handles are inherited. 

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT. 

    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
        printf(TEXT("StdoutRd CreatePipe"));

    // Ensure the read handle to the pipe for STDOUT is not inherited.

    if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
        printf(TEXT("Stdout SetHandleInformation"));

    // Create a pipe for the child process's STDIN. 

    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
        printf(TEXT("Stdin CreatePipe"));

    // Ensure the write handle to the pipe for STDIN is not inherited. 

    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
        printf(TEXT("Stdin SetHandleInformation"));


    STARTUPINFO siStartInfo;
    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    PROCESS_INFORMATION piProcInfo;
    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    TCHAR szCmdline[] = TEXT("powershell.exe");

    BOOL bSuccess = CreateProcess(NULL,
        szCmdline,     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        0,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION 
    // If an error occurs, exit the application. 

    if (!bSuccess) {
        printf(TEXT("Error creating process\n"));
       
    }
    else
    {
        // Close handles to the child process and its primary thread.
        // Some applications might keep these handles to monitor the status
        // of the child process, for example. 

        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);
    }

    struct data_arg data_arg = {g_hChildStd_IN_Wr, g_hChildStd_OUT_Rd };


    cb.userdata = &data_arg;

#else
    childpid = forkpty(&fd, NULL, term, win);
    if (childpid == 0) {
        execl("/bin/bash", "/bin/bash", (char *)NULL);
        abort();
    }
    SSHServer::cb.userdata = &fd;
#endif // _WIN32

    ssh_callbacks_init(&cb);
    if (ssh_set_channel_callbacks(chan, &cb) == SSH_ERROR) {
        printf("Couldn't set callbacks\n");
        return -1;
    }


    event = ssh_event_new();
    if (event == NULL) {
        printf("Couldn't get a event\n");
        return -1;
    } 


#ifndef _WIN32
    short events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
    if (ssh_event_add_fd(event, fd, events, copy_fd_to_chan, chan) != SSH_OK) {
        printf("Couldn't add an fd to the event\n");
        return -1;
    }
#endif
    if (ssh_event_add_session(event, session) != SSH_OK) {
        printf("Couldn't add the session to the event\n");
        return -1;
    }


    do {
#ifdef _WIN32
        copy_fd_to_chan_win(chan, &data_arg);
        ssh_event_dopoll(event, 100);
        //Sleep(1000);
#else
        ssh_event_dopoll(event, 1000);
#endif // _WIN32

    } while (!ssh_channel_is_closed(chan));

    ssh_event_remove_fd(event, fd);

    ssh_event_remove_session(event, session);

    ssh_event_free(event);
    return 0;
}

int SSHServer::sessionHandler(ssh_session session){
    ssh_message message;
    ssh_channel chan = 0;
    int shell = 0;
    int auth = 0;

    if (ssh_handle_key_exchange(session)) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return 1;
    }

    /* proceed to authentication */
    auth = SSHServer::authenticate(session);
    if (!auth) {
        printf("Authentication error: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        return 1;
    }

    /* wait for a channel session */
    do {
        message = ssh_message_get(session);
        if (message) {
            if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
                ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
                chan = ssh_message_channel_request_open_reply_accept(message);
                ssh_message_free(message);
                break;
            }
            else {
                ssh_message_reply_default(message);
                ssh_message_free(message);
            }
        }
        else {
            break;
        }
    } while (!chan);

    if (!chan) {
        printf("Error: cleint did not ask for a channel session (%s)\n",
            ssh_get_error(session));
        ssh_finalize();
        return 1;
    }


    /* wait for a shell */
    do {
        message = ssh_message_get(session);
        if (message != NULL) {
            if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
                    shell = 1;
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    break;
                }
                else if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    continue;
                }
            }
            ssh_message_reply_default(message);
            ssh_message_free(message);
        }
        else {
            break;
        }
    } while (!shell);

    if (!shell) {
        printf("Error: No shell requested (%s)\n", ssh_get_error(session));
        return 1;
    }

    printf("Connected \n");

    return SSHServer::main_loop(chan);
}

int SSHServer::run(int port) {
    if (priv_key.empty()) {
        printf("[-] There is no RSA key to start the SSH server");
        return 1;
    }

    ssh_event event;
    /* Create and configure the ssh session. */
    auto sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, ip);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY_MEMORY, priv_key.c_str());
    //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "C:\\Users\\alberto.garcia\\Desktop\\priv_key.txt");
    

    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
        return -1;
    }
    if (true) { printf("Listening on port %d.\n", port); }

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {    
        ssh_session session = ssh_new();
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: %s'.\n", ssh_get_error(sshbind));
            return -1;
        }
        if (true) { printf("Accepted a connection.\n"); }
        event = ssh_event_new();
        std::thread(SSHServer::sessionHandler, session).detach();
    }
}




