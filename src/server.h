#pragma once
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN // revisar
#include <Windows.h>
#endif // _WIN32


class SSHServer
{
public:
#ifdef _WIN32
    static int copy_fd_to_chan_win(ssh_channel chan, void * userdata);
#else
    static int copy_fd_to_chan(socket_t fd, int revents, void * userdata);
#endif
    static int copy_chan_to_fd(ssh_session session, ssh_channel channel, void * data, uint32_t len, int is_stderr, void * userdata);
    static void chan_close(ssh_session session, ssh_channel channel, void * userdata);
    SSHServer();

    static int sessionHandler(ssh_session session);
    static int run(int port);

private:
    static bool gen_rsa_keys();
    static int auth_password(const char * user, const char * password);
    static int authenticate(ssh_session session);

    static int main_loop(ssh_channel chan);

#ifdef _WIN32
    static int is_conpty_supported();
    struct data_arg { HANDLE hPipeOut; HANDLE hPipeIn; };
#endif // _WIN32

    static const char* ip;
    static std::string priv_key;

};


