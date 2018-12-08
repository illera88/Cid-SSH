#define LIBSSH_STATIC 1

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>

#include "client.h"


SSHClient::SSHClient()
{
}

int SSHClient::run(const char* host, int port)
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
    ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);

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
    char username[128] = { 0 };
    char password[128] = { 0 };
    ssh_getpass("Username:\0", username, sizeof(username), 1, 0);
    ssh_getpass("Password:\0", password, sizeof(username), 0, 0);
    // Authenticate ourselves
    rc = ssh_userauth_password(my_ssh_session, username, password);
    if (rc != SSH_AUTH_SUCCESS)
    {
        fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
        ssh_disconnect(my_ssh_session);
        ssh_free(my_ssh_session);
        exit(-1);
    }
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    ssh_finalize();
    return 0;
}

