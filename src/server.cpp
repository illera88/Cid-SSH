#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include <thread>

#include "server.h"
#include "shell-host.h"

// to generate RSA keys
#include <openssl/pem.h>

#ifdef IS_DEBUG
#define debug printf
#else  // just doesn't print the printf
#define debug(MESSAGE, ...)
#endif

std::string SSHServer::priv_key;
const char* SSHServer::ip="127.0.0.1";

typedef HRESULT(WINAPI *my_CreatePseudoHandle)(_In_ COORD,
    _In_ HANDLE,
    _In_ HANDLE,
    _In_ DWORD,
    _Out_ HPCON*);

typedef void(WINAPI *my_ClosePseudoHandle)(_Out_ HPCON);

SSHServer::SSHServer()
{
    if (gen_rsa_keys()) {
        debug("[+] RSA keys generated correctly\n");
    }
    else {
        debug("[+] Error generating RSA keys\n");
    }
}

#ifdef _WIN32
int SSHServer::copy_fd_to_chan_win(ssh_channel chan, void *userdata) {
    char buf[2048];
    int sz = 0;

    if (!chan) {
        struct data_arg my_data = *(struct data_arg*)userdata;
        CloseHandle(my_data.hPipeOut);

        return -1;
    }
    
    struct data_arg my_data = *(struct data_arg*)userdata;
    DWORD n_to_read;
    PeekNamedPipe(my_data.hPipeIn, NULL, NULL, NULL, &n_to_read, NULL);

    if (n_to_read == 0)
        return 0;

    DWORD dwRead = 0;
    bool SUCCESS = ReadFile(my_data.hPipeIn, buf, 2048, &dwRead, NULL);
    debug("Error %d\n", GetLastError());
    sz = (int)dwRead;

    if (sz > 0) {
        ssh_channel_write(chan, buf, sz);
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
    struct data_arg my_data = *(struct data_arg*)userdata;
    DWORD dwWritten = 0;
    BOOL SUCCESS = WriteFile(my_data.hPipeOut, data, len, &dwWritten, NULL);
    sz = (int)dwWritten;
#else
    int fd = *(int*)userdata;
    sz = write(fd, data, len);
#endif // _WIN32

    
    return sz;
}

void SSHServer::chan_close(ssh_session session, ssh_channel channel, void *userdata) {
#ifdef _WIN32
    struct data_arg my_data = *(struct data_arg*)userdata;
    CloseHandle(my_data.hPipeOut);
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


int SSHServer::auth_password(const char *user, const char *password) {
    return 1; // Always auth with any user/pass
    //if (strcmp(user, "alberto.garcia"))
    //    return 0;
    //if (strcmp(password, "123abc."))
    //    return 0;
    //return 1; // authenticated
}

int SSHServer::authenticate(ssh_session session) {
    ssh_message message;

    do {
        message = ssh_message_get(session);
        if (!message)
            break;
        switch (ssh_message_type(message)) {
        case SSH_REQUEST_AUTH:
            switch (ssh_message_subtype(message)) {
            case SSH_AUTH_METHOD_PASSWORD:
                debug("User %s wants to auth with pass %s\n",
                    ssh_message_auth_user(message),
                    ssh_message_auth_password(message));
                if (auth_password(ssh_message_auth_user(message),
                    ssh_message_auth_password(message))) {
                    ssh_message_auth_reply_success(message, 0);
                    ssh_message_free(message);
                    return 1;
                }
                ssh_message_auth_set_methods(message,
                    SSH_AUTH_METHOD_PASSWORD |
                    SSH_AUTH_METHOD_INTERACTIVE);
                // not authenticated, send default message
                ssh_message_reply_default(message);
                break;

            case SSH_AUTH_METHOD_NONE:
            default:
                debug("User %s wants to auth with unknown auth %d\n",
                    ssh_message_auth_user(message),
                    ssh_message_subtype(message));
                ssh_message_auth_set_methods(message,
                    SSH_AUTH_METHOD_PASSWORD |
                    SSH_AUTH_METHOD_INTERACTIVE);
                ssh_message_reply_default(message);
                break;
            }
            break;
        default:
            ssh_message_auth_set_methods(message,
                SSH_AUTH_METHOD_PASSWORD |
                SSH_AUTH_METHOD_INTERACTIVE);
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (1);
    return 0;
}

#ifdef _WIN32
int
SSHServer::is_conpty_supported()
{
    wchar_t system32_path[MAX_PATH] = { 0, };
    wchar_t kernel32_dll_path[MAX_PATH] = { 0, };
    HMODULE hm_kernelbase = NULL;
    static int isConpty = -1;

    if (isConpty != -1)
        return isConpty;

    isConpty = 0;
    if (!GetSystemDirectoryW(system32_path, MAX_PATH)) {
        debug("failed to get system directory");
        goto done;
    }

    wcscat_s(kernel32_dll_path, MAX_PATH, system32_path);
    wcscat_s(kernel32_dll_path, MAX_PATH, L"\\Kernel32.dll");

    if ((hm_kernelbase = LoadLibraryW(kernel32_dll_path)) == NULL) {
        debug("failed to load kernerlbase dll:%ls", kernel32_dll_path);
        goto done;
    }

    if (GetProcAddress(hm_kernelbase, "CreatePseudoConsole") == NULL) {
        debug("couldn't find CreatePseudoConsole() in kernerlbase dll");
        goto done;
    }

    isConpty = 1;
    debug("This windows OS supports conpty");
done:
    if (!isConpty) {
        debug("This windows OS doesn't support conpty");
    }
    return isConpty;
}
#endif

HRESULT CreatePseudoConsoleAndPipes(HPCON* phPC, HANDLE* phPipeIn, HANDLE* phPipeOut)
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

        HMODULE hModule = LoadLibrary(TEXT("Kernel32.dll"));

        my_CreatePseudoHandle my_CreatePseudoConsole_function =
            (my_CreatePseudoHandle)GetProcAddress(hModule, "CreatePseudoConsole");

        // Create the Pseudo Console of the required size, attached to the PTY-end of the pipes
        hr = my_CreatePseudoConsole_function(consoleSize, hPipePTYIn, hPipePTYOut, 0, phPC);

        FreeLibrary(hModule);

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
HRESULT InitializeStartupInfoAttachedToPseudoConsole(STARTUPINFOEX* pStartupInfo, HPCON hPC)
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


int SSHServer::main_loop(ssh_channel chan) {
    ssh_session session = ssh_channel_get_session(chan);
    socket_t fd = 1;
    struct termios *term = NULL;
    struct winsize *win = NULL;
#ifndef _WIN32
    pid_t childpid;
#endif
    ssh_event event;
    
    struct ssh_channel_callbacks_struct cb;
    cb.channel_data_function = SSHServer::copy_chan_to_fd;
    cb.channel_eof_function = SSHServer::chan_close;
    cb.channel_close_function = SSHServer::chan_close;
    cb.userdata = NULL;

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

    int cool_pty = is_conpty_supported();

    if (cool_pty) {
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

    PROCESS_INFORMATION piProcInfo;
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
    data_arg = { hPipeOut, hPipeIn };
    cb.userdata = &data_arg;

#else
    childpid = forkpty(&fd, NULL, term, win);
    if (childpid == 0) {
        execl("/bin/bash", "/bin/bash", (char *)NULL);
        abort();
    }
    SSHServer::cb.userdata = &fd;
#endif // _WIN32

    ssh_callbacks_init(&cb);
    if (ssh_set_channel_callbacks(chan, &cb) == SSH_ERROR) {
        debug("Couldn't set callbacks\n");
        return -1;
    }


    event = ssh_event_new();
    if (event == NULL) {
        debug("Couldn't get a event\n");
        return -1;
    } 


#ifndef _WIN32
    short events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
    if (ssh_event_add_fd(event, fd, events, copy_fd_to_chan, chan) != SSH_OK) {
        debug("Couldn't add an fd to the event\n");
        return -1;
    }
#endif
    if (ssh_event_add_session(event, session) != SSH_OK) {
        debug("Couldn't add the session to the event\n");
        return -1;
    }


    do {        
#ifdef _WIN32     
        GetExitCodeProcess(piProcInfo.hProcess, &exitCode);
        if (exitCode != STILL_ACTIVE)
            break;
        copy_fd_to_chan_win(chan, &data_arg);
        ssh_event_dopoll(event, 100);
        debug("Got: %d\n", exitCode);      
        //Sleep(1000);
#else
        ssh_event_dopoll(event, 1000);
#endif // _WIN32

    } while (!ssh_channel_is_closed(chan));

    
    if(!ssh_channel_is_closed(chan))
        ssh_channel_close(chan);

#ifdef _WIN32
    //Clean-up the pipes
    if (INVALID_HANDLE_VALUE != hPipeOut) CloseHandle(hPipeOut);
    if (INVALID_HANDLE_VALUE != hPipeIn) CloseHandle(hPipeIn);

    if (cool_pty) {
        // Cleanup attribute list
        DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        free(startupInfo.lpAttributeList);

        //Close ConPTY - this will terminate client process if running
        HMODULE hModule = LoadLibrary(TEXT("Kernel32.dll"));

        my_ClosePseudoHandle my_ClosePseudoConsole_function =
            (my_ClosePseudoHandle)GetProcAddress(hModule, "ClosePseudoConsole");

        // Create the Pseudo Console of the required size, attached to the PTY-end of the pipes
        my_ClosePseudoConsole_function(hPC);

        FreeLibrary(hModule);     
    }
#endif // _WIN32

    ssh_event_remove_fd(event, fd);

    ssh_event_remove_session(event, session);

    ssh_event_free(event);
    return 0;
}

int SSHServer::sessionHandler(ssh_session session){
    ssh_message message;
    ssh_channel chan = 0;
    int shell = 0;
    int auth = 0;

    if (ssh_handle_key_exchange(session)) {
        debug("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return 1;
    }

    /* proceed to authentication */
    auth = SSHServer::authenticate(session);
    if (!auth) {
        debug("Authentication error: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        return 1;
    }

    /* wait for a channel session */
    do {
        message = ssh_message_get(session);
        if (message) {
            if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
                ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
                chan = ssh_message_channel_request_open_reply_accept(message);
                ssh_message_free(message);
                break;
            }
            else {
                ssh_message_reply_default(message);
                ssh_message_free(message);
            }
        }
        else {
            break;
        }
    } while (!chan);

    if (!chan) {
        debug("Error: client did not ask for a channel session (%s)\n",
            ssh_get_error(session));
        ssh_finalize();
        return 1;
    }


    /* wait for a shell */
    do {
        message = ssh_message_get(session);
        if (message != NULL) {
            if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
                    shell = 1;
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    break;
                }
                else if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    continue;
                }
            }
            ssh_message_reply_default(message);
            ssh_message_free(message);
        }
        else {
            break;
        }
    } while (!shell);

    if (!shell) {
        debug("Error: No shell requested (%s)\n", ssh_get_error(session));
        return 1;
    }

    debug("Connected \n");

    return SSHServer::main_loop(chan);
}

int SSHServer::run(int port) {
    auto a = is_conpty_supported();
#ifdef IS_DEBUG
    int verbosity = SSH_LOG_PROTOCOL;
#else
    int verbosity = SSH_LOG_NOLOG;
#endif // DEBUG

    if (priv_key.empty()) {
        debug("[-] There is no RSA key to start the SSH server");
        return 1;
    }

    ssh_event event;
    /* Create and configure the ssh session. */
    auto sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, ip);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verbosity);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY_MEMORY, priv_key.c_str());
    //ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "C:\\Users\\alberto.garcia\\Desktop\\priv_key.txt");
    

    /* Listen on 'port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        debug("Error listening to socket: %s\n", ssh_get_error(sshbind));
        return -1;
    }
    if (true) { debug("Listening on port %d.\n", port); }

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {    
        ssh_session session = ssh_new();
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            debug("Error accepting a connection: %s'.\n", ssh_get_error(sshbind));
            return -1;
        }
        if (true) { debug("Accepted a connection.\n"); }
        event = ssh_event_new();
        std::thread(SSHServer::sessionHandler, session).detach();
    }
}




