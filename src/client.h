#pragma once

class SSHClient
{
public:
    SSHClient();

    static int run(const char* username, const char* host, int port);
private:

};