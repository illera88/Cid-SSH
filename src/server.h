#pragma once
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN // revisar
#include <Windows.h>
#endif // _WIN32



class SSHServer
{
	typedef HRESULT(WINAPI *my_CreatePseudoConsole)(_In_ COORD,
		_In_ HANDLE,
		_In_ HANDLE,
		_In_ DWORD,
		_Out_ HPCON*);

	typedef void(WINAPI *my_ResizePseudoConsole)(_In_ HPCON hPC, _In_ COORD size);

	typedef void(WINAPI *my_ClosePseudoConsole)(_Out_ HPCON);

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
    static int auth_password(ssh_session session, const char *user, const char *password, void *userdata);
    static int authenticate(ssh_session session);


	static int my_ssh_channel_pty_window_change_callback(ssh_session session, ssh_channel channel, int width, int height, int pxwidth, int pwheight, void * userdata);

	static int main_loop_shell();

	static int message_callback(ssh_session session, ssh_message message, void * userdata);

	static void conn_loop(ssh_event event, ssh_session session);

#ifdef _WIN32
    struct data_arg { HANDLE hPipeOut; HANDLE hPipeIn; };

	static my_CreatePseudoConsole my_CreatePseudoConsole_function;
	static my_ResizePseudoConsole my_ResizePseudoConsole_function;
	static my_ClosePseudoConsole my_ClosePseudoConsole_function;
	static HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEX * pStartupInfo, HPCON hPC);
	static HRESULT CreatePseudoConsoleAndPipes(HPCON * phPC, HANDLE * phPipeIn, HANDLE * phPipeOut);
#endif // _WIN32

	

	static int is_pty;
    static const char* ip;
    static std::string priv_key;


};


