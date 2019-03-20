#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <thread>
#include <chrono>

#include "server.h"

#if defined(__APPLE__)
#include <util.h>    //forkpty
#elif defined(__linux__)
#include <pty.h>    //forkpty
#endif

#include <assert.h>
#include <stdio.h>


#include "sts_queue.h"
#include "socks_proxy.h"


// to generate RSA keys
#include <openssl/pem.h>

#ifdef IS_DEBUG
#define debug printf
#else  // just doesn't print the printf
#define debug(MESSAGE, ...)
#endif

#ifdef _WIN32
#include <Windows.h>
#include <ws2tcpip.h>
#include <process.h> 
#else
#include <poll.h>
#define INVALID_HANDLE_VALUE -1
#endif // _WIN32

#ifdef HAVE_PTHREAD
#include <pthread.h>
typedef void* thread_rettype_t;
#else
typedef void thread_rettype_t;
#endif

std::string SSHServer::priv_key;
const char* SSHServer::ip="127.0.0.1";
int SSHServer::is_pty=0;
std::recursive_mutex mtx;

#ifdef _WIN32
SSHServer::my_CreatePseudoConsole SSHServer::my_CreatePseudoConsole_function = nullptr;
SSHServer::my_ResizePseudoConsole SSHServer::my_ResizePseudoConsole_function = nullptr;
SSHServer::my_ClosePseudoConsole SSHServer::my_ClosePseudoConsole_function = nullptr;
#endif

SSHServer::SSHServer()
{
    if (gen_rsa_keys()) {
        debug("[+] RSA keys generated correctly\n");
    }
    else {
        debug("[+] Error generating RSA keys\n");
    }

	/*Here we load dynamically the Windows pseudoTTY APIs*/
#ifdef _WIN32

	wchar_t system32_path[MAX_PATH] = { 0, };
	wchar_t kernel32_dll_path[MAX_PATH] = { 0, };
	HMODULE hm_kernelbase = NULL;


	if (!GetSystemDirectoryW(system32_path, MAX_PATH)) {
		debug("failed to get system directory\n");
		is_pty = 0;
		return;
	}

	wcscat_s(kernel32_dll_path, MAX_PATH, system32_path);
	wcscat_s(kernel32_dll_path, MAX_PATH, L"\\Kernel32.dll");

	if ((hm_kernelbase = LoadLibraryW(kernel32_dll_path)) == NULL) {
		debug("failed to load kernerlbase dll:%ls\n", kernel32_dll_path);
		is_pty = 0;
		return;
	}

	my_CreatePseudoConsole_function =
		(my_CreatePseudoConsole)GetProcAddress(hm_kernelbase, "CreatePseudoConsole");

	if (my_CreatePseudoConsole_function == NULL) {
		debug("couldn't find CreatePseudoConsole() in kernerlbase dll\n");
		debug("This windows OS doesn't support conpty\n");
		is_pty = 0;
		return;
	}

	my_ResizePseudoConsole_function =
		(my_ResizePseudoConsole)GetProcAddress(hm_kernelbase, "ResizePseudoConsole");

	my_ClosePseudoConsole_function =
		(my_ClosePseudoConsole)GetProcAddress(hm_kernelbase, "ClosePseudoConsole");

	this->is_pty = 1;
	debug("This windows OS supports conpty\n");

	FreeLibrary(hm_kernelbase);

#endif
}

#ifdef _WIN32
int SSHServer::windows_poll_channel(ssh_channel chan, void *userdata) {
    char buf[2048];
    int sz = 0;

    struct data_arg* my_data = (struct data_arg*)userdata;
    if (!chan) {     
        CloseHandle(my_data->hPipeOut);

        return -1;
    }
    
    DWORD n_to_read;
    PeekNamedPipe(my_data->hPipeIn, NULL, NULL, NULL, &n_to_read, NULL);

    if (n_to_read == 0)
        return 0;

    DWORD dwRead = 0;
    bool SUCCESS = ReadFile(my_data->hPipeIn, buf, 2048, &dwRead, NULL);

	sz = (int)dwRead;

    if (sz > 0) {
        pthread_mutex_lock(&my_data->thread_info->mutex);
        int size = ssh_channel_write(chan, buf, sz);
        pthread_mutex_unlock(&my_data->thread_info->mutex);
        if (size == SSH_ERROR) {  
            debug("Some error happened writting to the channel.\nError: %s\nerror code: %d\n", ssh_get_error(ssh_channel_get_session(chan)), ssh_get_error_code(ssh_channel_get_session(chan)));
            return -1;
        }
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
    struct data_arg* my_data = (struct data_arg*)userdata;
    DWORD dwWritten = 0;
    BOOL SUCCESS = WriteFile(my_data->hPipeOut, data, len, &dwWritten, NULL);
    sz = (int)dwWritten;
#else
    int fd = *(int*)userdata;
    sz = write(fd, data, len);
#endif // _WIN32

	/*if (sz > 1) {
		printf("aaa");
	}*/

	//strc
	//my_data.last_command.append((const char*)data, sz);
	////auto a = my_data.last_command.back();
	////debug("key %c\n", my_data.last_command.back());
	//if (*(const char*)data == '\r') {
	//	if (my_data.last_command == "tomate\r") {
	//		debug("command to exit received\n");
	//	}
	//	my_data.last_command.clear();
	//	
	//}

    return sz;
}

void SSHServer::chan_close(ssh_session session, ssh_channel channel, void *userdata) {
#ifdef _WIN32
    struct data_arg* my_data = (struct data_arg*)userdata;
    CloseHandle(my_data->hPipeOut);
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


int SSHServer::auth_password(ssh_session session, const char *user,
	const char *password, void *userdata) {
	struct thread_info_struct* args = (struct thread_info_struct*) userdata;
	args->authenticated = 1;
    return SSH_AUTH_SUCCESS; // Always auth with any user/pass
}

#ifdef _WIN32
HRESULT SSHServer::CreatePseudoConsoleAndPipes(HPCON* phPC, HANDLE* phPipeIn, HANDLE* phPipeOut)
{
    HRESULT hr{ E_UNEXPECTED };
    HANDLE hPipePTYIn{ INVALID_HANDLE_VALUE };
    HANDLE hPipePTYOut{ INVALID_HANDLE_VALUE };

    // Create the pipes to which the ConPTY will connect
    if (CreatePipe(&hPipePTYIn, phPipeOut, NULL, 0) &&
        CreatePipe(phPipeIn, &hPipePTYOut, NULL, 0))
    {
        // Determine required size of Pseudo Console
        COORD consoleSize{};
        CONSOLE_SCREEN_BUFFER_INFO csbi{};
        HANDLE hConsole{ GetStdHandle(STD_OUTPUT_HANDLE) };
        if (GetConsoleScreenBufferInfo(hConsole, &csbi))
        {
            consoleSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
            consoleSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
        }

        // Create the Pseudo Console of the required size, attached to the PTY-end of the pipes
        hr = SSHServer::my_CreatePseudoConsole_function(consoleSize, hPipePTYIn, hPipePTYOut, 0, phPC);

        // Note: We can close the handles to the PTY-end of the pipes here
        // because the handles are dup'ed into the ConHost and will be released
        // when the ConPTY is destroyed.
        if (INVALID_HANDLE_VALUE != hPipePTYOut) CloseHandle(hPipePTYOut);
        if (INVALID_HANDLE_VALUE != hPipePTYIn) CloseHandle(hPipePTYIn);
    }

    return hr;
}

// Initializes the specified startup info struct with the required properties and
// updates its thread attribute list with the specified ConPTY handle
HRESULT SSHServer::InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEX* pStartupInfo, HPCON hPC)
{
    HRESULT hr{ E_UNEXPECTED };

    if (pStartupInfo)
    {
        SIZE_T attrListSize{};

        pStartupInfo->StartupInfo.cb = sizeof(STARTUPINFOEX);

        // Get the size of the thread attribute list.
        InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

        // Allocate a thread attribute list of the correct size
        pStartupInfo->lpAttributeList =
            reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(malloc(attrListSize));

        // Initialize thread attribute list
        if (pStartupInfo->lpAttributeList
            && InitializeProcThreadAttributeList(pStartupInfo->lpAttributeList, 1, 0, &attrListSize))
        {
            // Set Pseudo Console attribute
            hr = UpdateProcThreadAttribute(
                pStartupInfo->lpAttributeList,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                hPC,
                sizeof(HPCON),
                NULL,
                NULL)
                ? S_OK
                : HRESULT_FROM_WIN32(GetLastError());
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    return hr;
}
#endif

int SSHServer::my_ssh_channel_pty_window_change_callback(ssh_session session,
	ssh_channel channel,
	int width, int height,
	int pxwidth, int pwheight,
	void *userdata) {
	// ToDo: We should resize the tty in this callback using ResizePseudoConsole
	// This callback is not called yet
#ifdef _WIN32
	if (SSHServer::is_pty) {
		// Create the Pseudo Console of the required size, attached to the PTY-end of the pipes
		COORD cords = { (short)width, (short)height };
		SSHServer::my_ResizePseudoConsole_function(NULL, cords);
	}
	else {}
#else
    // prob we need to use channel_pty_request_function cb
    // ToDo: https://github.com/cutwater/poc-sshserver/blob/55db7c5e68f93a997ca6cef8d8eac4cea161988d/main.c#L334
#endif
	return 1;
}


int SSHServer::main_loop_shell(ssh_session session, struct thread_info_struct* thread_info) {
    ssh_channel channel = thread_info->channel;
    socket_t fd = 1;
    struct termios *term = NULL;
    struct winsize *win = NULL;
#ifndef _WIN32
    pid_t childpid;
#endif
    ssh_event event = thread_info->event;

    struct ssh_channel_callbacks_struct cb;
    memset(&cb, '\x00', sizeof(cb));
    cb.channel_data_function = SSHServer::copy_chan_to_fd;
    cb.channel_eof_function = SSHServer::chan_close;
    cb.channel_close_function = SSHServer::chan_close;
	cb.channel_pty_window_change_function = SSHServer::my_ssh_channel_pty_window_change_callback;
    cb.userdata = NULL;

	// We will use this to store the commands executed to look for exit one
	std::string command_storage;
	command_storage.reserve(1024);

#ifdef _WIN32
    HANDLE g_hChildStd_IN_Rd = INVALID_HANDLE_VALUE;
    HANDLE hPipeOut = INVALID_HANDLE_VALUE;
    HANDLE hPipeIn = INVALID_HANDLE_VALUE;
    HANDLE g_hChildStd_OUT_Wr = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES saAttr;
    DWORD exitCode;
    HPCON hPC{ INVALID_HANDLE_VALUE };
    STARTUPINFO siStartInfo;
    PROCESS_INFORMATION piProcInfo;
    struct data_arg data_arg;
    STARTUPINFOEX startupInfo{};

    if (is_pty) {
        // Great! we can use https://blogs.msdn.microsoft.com/commandline/2018/08/02/windows-command-line-introducing-the-windows-pseudo-console-conpty/
        
        HRESULT hr{ E_UNEXPECTED };
        HANDLE hConsole = { GetStdHandle(STD_OUTPUT_HANDLE) };
        TCHAR szCmdline[] = "cmd.exe";

        // Enable Console VT Processing
        DWORD consoleMode{};
        GetConsoleMode(hConsole, &consoleMode);
        hr = SetConsoleMode(hConsole, consoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
            ? S_OK
            : GetLastError();
        if (S_OK == hr)
        {
            //  Create the Pseudo Console and pipes to it
            hr = CreatePseudoConsoleAndPipes(&hPC, &hPipeIn, &hPipeOut);
            if (S_OK == hr)
            {
                // Initialize the necessary startup info struct        
                
                if (S_OK == InitializeStartupInfoAttachedToPseudoConsole(&startupInfo, hPC))
                {
                    // Launch ping to emit some text back via the pipe
                    hr = CreateProcess(
                        NULL,                           // No module name - use Command Line
                        szCmdline,                      // Command Line
                        NULL,                           // Process handle not inheritable
                        NULL,                           // Thread handle not inheritable
                        FALSE,                          // Inherit handles
                        EXTENDED_STARTUPINFO_PRESENT,   // Creation flags
                        NULL,                           // Use parent's environment block
                        NULL,                           // Use parent's starting directory 
                        &startupInfo.StartupInfo,       // Pointer to STARTUPINFO
                        &piProcInfo)                      // Pointer to PROCESS_INFORMATION
                        ? S_OK
                        : GetLastError();
                }
            }
        }
    }
    else {
        /* ToDo: implement     //start_with_pty();*/

        // Set the bInheritHandle flag so pipe handles are inherited. 
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        // Create a pipe for the child process's STDOUT. 
        if (!CreatePipe(&hPipeIn, &g_hChildStd_OUT_Wr, &saAttr, 0)) {
            debug("StdoutRd CreatePipe");
        }

        // Ensure the read handle to the pipe for STDOUT is not inherited.
        if (!SetHandleInformation(hPipeIn, HANDLE_FLAG_INHERIT, 0)) {
            debug("Stdout SetHandleInformation");
        }

        // Create a pipe for the child process's STDIN. 
        if (!CreatePipe(&g_hChildStd_IN_Rd, &hPipeOut, &saAttr, 0)) {
            debug("Stdin CreatePipe");
        }

        // Ensure the write handle to the pipe for STDIN is not inherited. 
        if (!SetHandleInformation(hPipeOut, HANDLE_FLAG_INHERIT, 0)){
            debug("Stdin SetHandleInformation");
        }

        ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
        siStartInfo.cb = sizeof(STARTUPINFO);
        siStartInfo.hStdError = g_hChildStd_OUT_Wr;
        siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
        siStartInfo.hStdInput = g_hChildStd_IN_Rd;
        siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

        //char szCmdline[] = "C:\\WINDOWS\\System32\\cmd.exe /c cmd.exe";
        //TCHAR szCmdline[] = TEXT("C:\\WINDOWS\\System32\\powershell.exe");
        TCHAR szCmdline[] = TEXT("powershell.exe"); // For some weird reason it works fine with powershell but it does not with cmd.exe WHAAAAATTT?!?!
        //TCHAR szCmdline[] = TEXT("cmd.exe");
        //TCHAR szCmdline[] = TEXT("C:\\Users\\alberto.garcia\\Downloads\\OpenSSH-Win64\\ssh-shellhost.exe ---pty cmd.exe");
        //TCHAR szCmdline[] = TEXT("C:\\Users\\alberto.garcia\\Downloads\\OpenSSH-Win64\\ssh-shellhost.exe ---pty conhost.exe --headless");

        ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

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
            debug("Error creating process\n");
            // ToDo: need to return gratefully
        }
    }

	//data_arg = { hPipeOut, hPipeIn, {NULL}, 0 };
    data_arg = { hPipeOut, hPipeIn, thread_info };
    cb.userdata = &data_arg;

#else
    childpid = forkpty(&fd, NULL, term, win);
    if (childpid == 0) {
        execl("/bin/bash", "/bin/bash", (char *)NULL);
        abort();
    }
    cb.userdata = &fd;
#endif // _WIN32

    ssh_callbacks_init(&cb);
    if (ssh_set_channel_callbacks(channel, &cb) == SSH_ERROR) {
        debug("Couldn't set callbacks\n");
        return -1;
    }

#ifndef _WIN32
    short events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
    if (ssh_event_add_fd(event, fd, events, copy_fd_to_chan, channel) != SSH_OK) {
        debug("Couldn't add an fd to the event\n");
        return -1;
    }
#endif
   /* if (ssh_event_add_session(event, session) != SSH_OK) {
        debug("Couldn't add the session to the event\n");
        return -1;
    }*/


    do {        
#ifdef _WIN32     
        GetExitCodeProcess(piProcInfo.hProcess, &exitCode);
        if (exitCode != STILL_ACTIVE)
            break;

        windows_poll_channel(channel, &data_arg);

        
        //ssh_event_dopoll(event, 100);

#else
        //ssh_event_dopoll(event, 1000);
#endif // _WIN32
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

    } while (!ssh_channel_is_closed(channel));

    
    if(!ssh_channel_is_closed(channel))
        ssh_channel_close(channel);
    
    ssh_remove_channel_callbacks(channel, &cb);

#ifdef _WIN32
    //Clean-up the pipes
    if (INVALID_HANDLE_VALUE != hPipeOut) CloseHandle(hPipeOut);
    if (INVALID_HANDLE_VALUE != hPipeIn) CloseHandle(hPipeIn);

    if (is_pty) {
        // Cleanup attribute list
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        free(startupInfo.lpAttributeList);

        // Create the Pseudo Console of the required size, attached to the PTY-end of the pipes
        SSHServer::my_ClosePseudoConsole_function(hPC);

    }
#else // _WIN32
    ssh_event_remove_fd(event, fd);
#endif

    return 0;
}





/* Return 1 if you want libshh to handle the message properly. 0 if you did*/
int SSHServer::message_callback(ssh_session session, ssh_message message, void *userdata) {
    struct thread_info_struct* thread_info = (struct thread_info_struct*)userdata;

	auto type = ssh_message_type(message);
	auto subtype = ssh_message_subtype(message);
	debug("Message type: %d\n", type);
	debug("Message Subtype: %d\n", subtype);
	switch (type)
	{
	case SSH_REQUEST_CHANNEL_OPEN: {
		debug("SSH_REQUEST_CHANNEL_OPEN\n");
		switch (subtype)
		{
		case SSH_CHANNEL_DIRECT_TCPIP: { //SOCKS5	
            return handle_socks_connection(message, thread_info);
		}

		case SSH_CHANNEL_SESSION: {
			debug("SSH_CHANNEL_SESSION\n");
			ssh_channel channel = ssh_message_channel_request_open_reply_accept(message);			
			if (!channel) {
				return 1;
			}
			thread_info->channel = channel;
			return 0;
		}
		default:
			return 1;
		}
		break;
	}
	case SSH_REQUEST_CHANNEL: {
		debug("SSH_REQUEST_CHANNEL\n");
		switch (subtype)
		{
		case SSH_CHANNEL_REQUEST_SHELL: {
			ssh_message_channel_request_reply_success(message);
            if (thread_info->channel == NULL) {
                debug("Weird that we are getting SSH_CHANNEL_REQUEST_SHELL and we did not get SSH_CHANNEL_SESSION before\n");
                return 1;
            }
			std::thread(main_loop_shell, session, thread_info).detach();
			return 0;
		}
		case SSH_CHANNEL_REQUEST_PTY: {
			ssh_message_channel_request_reply_success(message);
			return 0;
		}
		default:
			return 1;
		}
	}
	default:
		return 1;
	}
	return 1;
}


thread_rettype_t SSHServer::per_conn_thread(void* args){
    struct thread_info_struct info;
    info.authenticated = 0;
    info.error = 0;
    info.session = 0;
    info.sockets_cnt = 0;
    info.cleanup_queue = StsQueue.create();
    info.dynamic_port_fwr = 0;
    info.queue = nullptr;
    info.channel = nullptr;
#ifdef _WIN32
    InitializeCriticalSection(&info.mutex);
#else
    pthread_mutex_init(&info.mutex, NULL);
#endif // _WIN32

    info.connection_thread = INVALID_HANDLE_VALUE;
    info.session = (ssh_session)args;

    struct ssh_server_callbacks_struct cb;
    memset(&cb, '\x00', sizeof (cb));
    cb.userdata = &info;
    cb.auth_password_function = auth_password;

    ssh_set_log_level(SSH_LOG_FUNCTIONS);

    ssh_callbacks_init(&cb);
    ssh_set_server_callbacks(info.session, &cb);
    ssh_set_message_callback(info.session, SSHServer::message_callback, &info);

    if (ssh_handle_key_exchange(info.session)) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(info.session));
        goto shutdown;
    }
    ssh_set_auth_methods(info.session, SSH_AUTH_METHOD_PASSWORD);

    info.event = ssh_event_new();

    ssh_event_add_session(info.event, info.session);

    while (!info.authenticated) {
        if (info.error)
            break;
        if (ssh_event_dopoll(info.event, -1) == SSH_ERROR) {
            printf("Error : %s\n", ssh_get_error(info.session));
            info.error = 1;
            goto shutdown;
        }
    }
    if (info.error) {
        printf("Error, exiting loop\n");
    }
    else {
        printf("Authenticated and got a channel\n");

        while (!info.error) {
            pthread_mutex_lock(&info.mutex);
            int err = ssh_event_dopoll(info.event, 50);
            pthread_mutex_unlock(&info.mutex);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (err == SSH_ERROR) {
                printf("Error : %s\n", ssh_get_error(info.session));
                info.error = 1;
                goto shutdown;
            }

            if (info.dynamic_port_fwr) {
                do_cleanup(info.cleanup_queue);
                do_set_callbacks(&info);
            }
        }
    }
shutdown:
    if (info.dynamic_port_fwr) {
#ifdef _WIN32
        WaitForSingleObject(info.connection_thread, INFINITE);
#else
        pthread_join(info.connection_thread, NULL);
#endif
        StsQueue.destroy(info.queue);
    }

    pthread_mutex_destroy(&info.mutex);
    if (ssh_is_connected(info.session))
        ssh_disconnect(info.session);

    ssh_event_remove_session(info.event, info.session);
    if (info.channel != NULL)
        ssh_channel_free(info.channel);
    ssh_event_free(info.event);
    
    ssh_free(info.session);
    
    debug("Closing session\n");

#ifdef HAVE_PTHREAD
    return NULL;
#endif
}

int SSHServer::run(int port) {
#ifdef IS_DEBUG
    int verbosity = SSH_LOG_FUNCTIONS;
#else
    int verbosity = SSH_LOG_NOLOG;
#endif // DEBUG

    if (priv_key.empty()) {
        debug("[-] There is no RSA key to start the SSH server");
        return 1;
    }

	ssh_session session;
    /* Create and configure the ssh session. */
    ssh_bind sshbind = ssh_bind_new();

    //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, ip);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY_MEMORY, priv_key.c_str());
    

    /* Listen on 'port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        debug("Error listening to socket: %s\n", ssh_get_error(sshbind));
        return -1;
    }
    debug("Listening on port %d.\n", port);

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {
        session = ssh_new();

        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            printf("error accepting a connection : %s\n", ssh_get_error(sshbind));
            goto shutdown;
        }

#ifdef HAVE_PTHREAD
        pthread_t thread;
        int rc = pthread_create(&thread, NULL, per_conn_thread, session);
        if (rc != 0) {
            printf("Error starting thread: %d\n", rc);
            return 1;
        }
#else
        _beginthread(per_conn_thread, 0, session);
#endif // HAVE_PTHREAD
    }

shutdown:
	ssh_bind_free(sshbind);
	ssh_finalize();
	return 0;
}


