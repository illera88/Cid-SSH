#pragma once

#define CLIENT_SENT_EOF -6
#define SERVICE_SENT_EOF -5
#define SERVICE_CONN_ERROR -4
#define SSH_SENT_EOF -3
#define SYSTEM_ERROR -2

#define ACCEPT_FORWARD_TIMEOUT 15000	// ms

class SSHClient
{
public:
    SSHClient();

	

	static int run(const char* username, const char* host, int port);
private:
	static int should_terminate;
	static int connect_to_local_service(int port);
	static int do_remote_forwarding_loop(ssh_session session, ssh_channel channel, int lport);
	static void remote_forwading_thread(ssh_session sess, ssh_channel chan, int lport);
	static int do_remote_forwarding(ssh_session sess, int lport, int rport);
};