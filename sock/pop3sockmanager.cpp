#include "pop3sockmanager.h"

namespace pop3
{
	pop3socket::POP3_SOCKET_STATUS_E 
		SocketManager::SocketConnect(const string& server, const unsigned int port)
	{
		this->server = server;
		this->portNo = port;

		struct addrinfo hints, *result;

    	hints.ai_flags = AI_CANONNAME|AI_CANONIDN;
    	hints.ai_family = AF_UNSPEC;
    	hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = 0;

		string str_port; 
		pop3_type_to_string(port, str_port);

    	int ret = getaddrinfo(server.c_str(), str_port.c_str(), &hints, &result);

    	if(ret != 0)
    	{
        	POP3_DEBUG(pop3debug::POP3_DEBUG_INTERNAL, "Error in getaddrinfo %s\n", gai_strerror(ret));
			if(ret == EAI_AGAIN || ret == EAI_FAIL || ret == EAI_NONAME)
			{
				return pop3socket::POP3_SOCKET_HOST_ERROR;
			}

			if(ret == EAI_FAMILY)
			{
				return pop3socket::POP3_SOCKET_UNSUPPORTED;
			}

			return pop3socket::POP3_SOCKET_INTERNAL;
    	}

		//This will go out of scope once freeaddrinfo is called. Try an alternative
		//ipaddr = result->ai_addr;
    	sockFd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    	if(sockFd == -1)
    	{
			err = errno;
        	POP3_DEBUG(pop3debug::POP3_DEBUG_INTERNAL, "Socket creation problem\n");
			if(result)
			{
				freeaddrinfo(result);
			}
			return MapErrNumber(err);
		}
		
		/*
			Do connect to server so that even if SSL is enabled, 
		 	we can attach connected fd to SSL library
		*/
		SocketSetNonBlocking(sockFd);
		pop3socket::POP3_SOCKET_STATUS_E sock_status;

		if(pop3_is_link_local_ip(result->ai_addr))
		{
			sock_status = LinkLocalConnect(sockFd, result->ai_addr, result->ai_addrlen);
		}
		else
		{
			sock_status = TimedConnect(sockFd, result->ai_addr, result->ai_addrlen);
		}

		pop3_ip_to_host(result->ai_addr, result->ai_addrlen, true, hostname);

		SocketSetBlocking(sockFd);

		if(result)
		{
			freeaddrinfo(result);
		}

		if(sock_status != pop3socket::POP3_SOCKET_OK)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Connection to specified server failed\n");
			return sock_status;
		}

		// Do not initiate SSL in Connect State for start tls
		if(ssl_mode > pop3ssl::POP3_START_TLS)
		{
			return SSLConnect();
		}
			
		return pop3socket::POP3_SOCKET_OK;
	}

	pop3socket::POP3_SOCKET_STATUS_E 
			SocketManager::SocketRead(char* buffer, const size_t length, int& bytesRead)
	{
		pop3socket::POP3_SOCKET_STATUS_E waitStatus = Pop3Wait();
	
		if(waitStatus != pop3socket::POP3_SOCKET_OK)
		{
			return waitStatus;
		}

		if(ssl_mode > pop3ssl::POP3_START_TLS)
		{
			return SSLRead(buffer, length, bytesRead);
		}
	
		bytesRead = recv(sockFd, buffer, length, 0);
		if(bytesRead == -1)
		{
			err = errno;
			return MapErrNumber(err);
		}

		if(bytesRead == 0)
		{
			return pop3socket::POP3_SOCKET_CONN_CLOSED;
		}
	
		return pop3socket::POP3_SOCKET_OK;
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SocketManager::SocketWrite(const char* buffer, const size_t length)
	{
		if(ssl_mode > pop3ssl::POP3_START_TLS)
        {
            return SSLWrite(buffer, length);
        }

		int ret = send(sockFd, buffer, length, MSG_NOSIGNAL);
		
		if(ret == -1)
		{
			err = errno;
			return MapErrNumber(err);
		}

		return pop3socket::POP3_SOCKET_OK;
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SocketManager::SocketDisconnect()
	{
		if(ssl_mode > pop3ssl::POP3_START_TLS)
        {
			SSLDisconnect();
		}

		if(sockFd > 0)
		{
			close(sockFd);
			sockFd = -1;
		}

		is_disconnected = true;

		return pop3socket::POP3_SOCKET_OK;
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SocketManager::SocketStartTls()
	{		
		pop3socket::POP3_SOCKET_STATUS_E stlsStatus = SSLConnect();
		if(stlsStatus != pop3socket::POP3_SOCKET_OK)
		{
			return stlsStatus;
		}

		ssl_mode = pop3ssl::POP3_SSL;

		return pop3socket::POP3_SOCKET_OK;
	}

	void SocketManager::SocketGetHostName(string& host_name)
	{
		host_name = this->hostname;
	}

	/* Private Interfaces */
	pop3socket::POP3_SOCKET_STATUS_E 
			SocketManager::SSLInit()
	{
		return sslWrapper.SSLInit();
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SocketManager::SSLConnect()
	{
		if(SSLInit() != pop3socket::POP3_SOCKET_OK)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_INTERNAL, "SSL Initialization failed\n");
			return pop3socket::POP3_SOCKET_FAIL;
		}

		return sslWrapper.SSLConnect(sockFd, sslVerifyType, ca_certificate_path, ca_client_cert, server);
	}

	pop3socket::POP3_SOCKET_STATUS_E 
			SocketManager::SSLRead(char* buffer, const size_t bufSize, int& bytesRead)
	{
		return sslWrapper.SSLRead(buffer, bufSize, bytesRead);
	}
	
	pop3socket::POP3_SOCKET_STATUS_E 
			SocketManager::SSLWrite(const char* data, const size_t sendLen)
	{
		return sslWrapper.SSLWrite(data, sendLen);
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SocketManager::SSLDisconnect()
	{		
		return sslWrapper.SSLDisconnect();
	}

	pop3socket::POP3_SOCKET_STATUS_E 
			SocketManager::MapErrNumber(const int err)
	{
		switch(err)		
		{
			case EAFNOSUPPORT:
			case EPROTONOSUPPORT:
				return pop3socket::POP3_SOCKET_UNSUPPORTED;

			case ECONNREFUSED:
				if(ssl_mode > pop3ssl::POP3_SSL_DISABLE)
					return pop3socket::POP3_SOCKET_SSL_UNSUPPORTED;
				else
					return pop3socket::POP3_SOCKET_SERV_UNSUPPORTED;

			case ENETUNREACH:
				return pop3socket::POP3_SOCKET_FAIL;
	
			case ETIMEDOUT:
				return pop3socket::POP3_SOCKET_TIMEOUT;

			case ECONNRESET:
				return pop3socket::POP3_SOCKET_CONN_RESET;

			case ENOTCONN:
				return pop3socket::POP3_SOCKET_NOT_CONNECTED;
			
			case EPIPE:
				return pop3socket::POP3_SOCKET_CONN_CLOSED;

			default:			
				return pop3socket::POP3_SOCKET_INTERNAL;
		}
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SocketManager::Pop3Wait()
	{
		fd_set inputSet;
		FD_ZERO(&inputSet);
		FD_SET(sockFd, &inputSet);

		struct timeval socket_time = {timeout, 0};

		int ret = select(FD_SETSIZE, &inputSet, NULL, NULL, &socket_time);
		FD_CLR(sockFd, &inputSet);
		
		if (ret > 0)
		{
			return pop3socket::POP3_SOCKET_OK;
		}

		if(ret == 0)
		{
			return pop3socket::POP3_SOCKET_TIMEOUT;
		}

		return MapErrNumber(ret);	
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SocketManager::TimedConnect(const int fd, const sockaddr* addr, const socklen_t sock_len, const bool un_retry)
	{
		fd_set con_set;

		int con_ret = connect(fd, addr, sock_len);

		if(con_ret != 0)
		{
			int error_code = errno;
			
			if(error_code == EINPROGRESS)
			{
				struct timeval connect_time = {timeout, 0};
				FD_ZERO(&con_set);
				FD_SET(fd, &con_set);
	
retry:			int select_ret = select(fd+1, NULL, &con_set, NULL, &connect_time);
				if(select_ret > 0)
				{
					//select event
					int sock_error = 0;
					socklen_t opt_len = sizeof(sock_error);
					getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_error, &opt_len);

					if(sock_error == 0)
					{
						//connection succeeded
						POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "Connection successful \n");
						return pop3socket::POP3_SOCKET_OK;
					}
					else
					{
						if(sock_error == EHOSTUNREACH || sock_error == EALREADY)
						{
							//Host unreachable? retry until select times out if un_retry=true
							POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Retry connection till timeout\n");
							if(un_retry)
								goto retry;
							return pop3socket::POP3_SOCKET_FAIL;
						}
						//Connection failed
						POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Pop3 Connection failed-1, error=%s\n", strerror(sock_error));
						return MapErrNumber(sock_error);
					}
				}
				else if(select_ret == 0)
				{
					//connect time-out
					POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Pop3 Connection Timedout\n");
					return pop3socket::POP3_SOCKET_TIMEOUT;
				}
				else
				{
					//system call error
					POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, "select() system call fail\n");
					return pop3socket::POP3_SOCKET_INTERNAL;
				}
			}
			else
			{
				//Error in connect	
				POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Pop3 Connection failed-2 %d = %s\n", errno, strerror(errno));
				return pop3socket::POP3_SOCKET_FAIL;
			}
		}

		POP3_DEBUG(pop3debug::POP3_DEBUG_INFO2, "Pop3 Connection succeeded\n");
		return pop3socket::POP3_SOCKET_OK;
	}

	pop3socket::POP3_SOCKET_STATUS_E
		SocketManager::LinkLocalConnect(const int fd, const sockaddr* addr, const socklen_t sock_len)
	{
		/*
			For link-local it is difficult to determine the zone if there are multiple interfaces
			Just make use of ioctl calls to iterate through all interfaces except loopback ('lo')
			Since link-local is within LAN, connection may not take much time and delay because of iteration may not be considerable
		*/
		
		struct ifreq if_req;
        if_req.ifr_ifindex = 1;
		pop3socket::POP3_SOCKET_STATUS_E sock_status = pop3socket::POP3_SOCKET_FAIL;

		while(ioctl(fd, SIOCGIFNAME, &if_req) != -1)
		{
			if(strcasecmp(if_req.ifr_name, "lo") == 0)
			{
				POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "Loopback interface found.. Skipping\n");
				if_req.ifr_ifindex++;
				continue;
			}

			struct sockaddr_in6 *temp= (struct sockaddr_in6*)(addr);
			temp->sin6_scope_id = if_req.ifr_ifindex;

			if((sock_status = TimedConnect(fd, addr, sock_len, false)) != pop3socket::POP3_SOCKET_OK)
			{
				POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Connect failed with interface index=%d, name=%s\n", if_req.ifr_ifindex, if_req.ifr_name);
				if_req.ifr_ifindex++;
				continue;
			}

			POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "Connected with interface index=%d, name=%s\n", if_req.ifr_ifindex, if_req.ifr_name);
			return pop3socket::POP3_SOCKET_OK;
		}

		POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Unable to connect via any interface for Link Local IP\n");
		return sock_status;
	}

	bool
		SocketManager::SocketSetNonBlocking(const int fd)
	{
		int flags = 0;
		flags = fcntl(fd, F_GETFL, 0);
		if(flags < 0)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Could not get flags for fd=%d\n", fd);
			return false;
		}

		flags |= O_NONBLOCK;

		if(fcntl(fd, F_SETFL, flags) < 0)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Could not set fd=%d to non blocking mode\n", fd);
			return false;
		}

		return true;
	}

	bool
		SocketManager::SocketSetBlocking(const int fd)
	{
		int flags = 0;
		flags = fcntl(fd, F_GETFL, 0);
		if(flags < 0)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Could not get flags for fd=%d\n", fd);
			return false;
		}

		if((flags & O_NONBLOCK) == O_NONBLOCK)
		{
			flags &= (~O_NONBLOCK);
			if(fcntl(fd, F_SETFL, flags) < 0)
			{
				POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Could not set fd=%d to blocking mode\n", fd);
				return false;
			}
		}

		return true;
	}
}
