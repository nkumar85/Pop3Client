#include "common/pop3defs.h"
#include "common/pop3utils.h"
#include "debug/pop3debug.h"
#include "wrapper/pop3sslwrapper.h"

#ifndef __POP3_SOCK__MANAGER__H
#define __POP3_SOCK__MANAGER__H

namespace pop3
{
	namespace pop3ssl
    {
        typedef enum
        {
            POP3_SSL_DISABLE,
            POP3_START_TLS,
            POP3_SSL
        }Pop3Ssl;
    }

	namespace pop3verifytype
	{
		typedef enum
		{			
            POP3_SSL_ACCEPT_IMPORTED_CERT,
            POP3_SSL_VERIFY_IMPORTED_CERT,
		}Pop3VerifyType;
	}

	class SocketManager
	{
		private:
			int sockFd;
			unsigned int portNo, timeout, err;
			pop3ssl::Pop3Ssl ssl_mode;
			pop3verifytype::Pop3VerifyType sslVerifyType;
			string ca_certificate_path, ca_client_cert, server;
			bool is_disconnected;
			sockaddr* ipaddr;
			string hostname;
			
			SSLWrapper sslWrapper;

			pop3socket::POP3_SOCKET_STATUS_E SSLInit();
			pop3socket::POP3_SOCKET_STATUS_E SSLConnect();
			pop3socket::POP3_SOCKET_STATUS_E SSLRead(char* buffer, const size_t bufSize, int& bytesRead);
			pop3socket::POP3_SOCKET_STATUS_E SSLWrite(const char* data, const size_t sendLen);
			pop3socket::POP3_SOCKET_STATUS_E SSLDisconnect();
			pop3socket::POP3_SOCKET_STATUS_E MapErrNumber(const int err);
			pop3socket::POP3_SOCKET_STATUS_E Pop3Wait();
			pop3socket::POP3_SOCKET_STATUS_E TimedConnect(const int fd, const sockaddr* addr, const socklen_t sock_len, const bool un_retry = true);
			pop3socket::POP3_SOCKET_STATUS_E LinkLocalConnect(const int fd, const sockaddr* addr, const socklen_t sock_len);
			bool SocketSetNonBlocking(const int fd);
			bool SocketSetBlocking(const int fd);

		public:
			SocketManager(	const unsigned int timeout,
							const pop3ssl::Pop3Ssl ssl = pop3ssl::POP3_SSL_DISABLE,
							const pop3verifytype::Pop3VerifyType sslVerifyType = pop3verifytype::POP3_SSL_ACCEPT_IMPORTED_CERT,
							const string& ca_cert_path = "",
							const string& ca_client_cert = "" 
						) : portNo(pop3defaults::POP3_SERVER_PORT), timeout(timeout), err(0),
							ssl_mode(ssl), sslVerifyType(sslVerifyType), ca_certificate_path(ca_cert_path),
							ca_client_cert(ca_client_cert), is_disconnected(false)
			{
			}

			~SocketManager()
			{
				SocketDisconnect();
			}

			pop3socket::POP3_SOCKET_STATUS_E SocketConnect(const string& server, const unsigned int port);
			pop3socket::POP3_SOCKET_STATUS_E SocketStartTls();
			pop3socket::POP3_SOCKET_STATUS_E SocketRead(char* buffer, const size_t length, int& bytesRead);
			pop3socket::POP3_SOCKET_STATUS_E SocketWrite(const char* buffer, const size_t length);
			pop3socket::POP3_SOCKET_STATUS_E SocketDisconnect();
			bool IsSocketDisconnected() { return is_disconnected;}
			void SocketGetHostName(string& host_name);
	};
}

#endif
