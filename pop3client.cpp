#include "pop3client.h"
#include <common/pop3utils.h>
#include <common/pop3strtoken.h>
//#include "pop3digestmd5.h"
//#include "pop3krb5wrapper.h"
//#include "pop3saslmanager.h"

namespace pop3
{
	template pop3status::Pop3Status Pop3Client::RetrieveList(map<unsigned int, unsigned int>& uid_list, const string& command, const bool multi_line);
	template pop3status::Pop3Status Pop3Client::RetrieveList(map<unsigned int, string>& uid_list, const string& command, const bool multi_line);
	template pop3status::Pop3Status Pop3Client::RetrieveList(map<string, string>& uid_list, const string& command, const bool multi_line);

	pop3status::Pop3Status
		RetrCallbackBegin(void* context, void* data, size_t data_size, unsigned int mail_index)
	{
		POP3_DEBUG_INFO2("Callback begin called with byte size : %d\n", data_size);
		int* fd = static_cast<int*>(context);
		write(*fd, data, data_size);
		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		RetrCallbackEnd(void* context, void* data, size_t data_size, unsigned int mail_index)
	{
		POP3_DEBUG_INFO2("Callback end called with byte size : %d\n", data_size);
		int* fd = static_cast<int*>(context);
		write(*fd, data, data_size);
		close(*fd);
		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Init()
	{
		POP3_CHECK_STATE(INIT);

		if(currentSettings.host == "")
		{
			POP3_DEBUG_SEVERE("Host/IP not provided\n");
			goto error;
		}
		
		if(currentSettings.portNo == 0)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, "Invalid port number specified\n");
			goto error;
		}

		if(currentSettings.sslEnable < pop3ssl::POP3_SSL_DISABLE || currentSettings.sslEnable > pop3ssl::POP3_SSL)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, "Invalid SSL settings specified\n");
			goto error;
		}
		else
		{
			if(currentSettings.sslEnable > pop3ssl::POP3_SSL_DISABLE)
			{
				if(currentSettings.sslVerifyType == pop3verifytype::POP3_SSL_VERIFY_IMPORTED_CERT && currentSettings.ca_path == "")
				{
					POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, "SSL CA verification requires valid CA file\n");
					currentSettings.ca_path = pop3defaults::SSL_CA_PATH;
				}
			}
		}

		if(currentSettings.pop3Auth < pop3auth::POP3 || currentSettings.pop3Auth > pop3auth::SASL_GSSAPI)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, "Invalid auth type specified \n");
			goto error;
		}

		if(currentSettings.pop3User == "")
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, "Pop3 user id is not specified\n");
			goto error;
		}
	
		if(currentSettings.pop3Pass == "")
		{
			//Do we need validation?
		}

		POP3_SET_STATE(GREETING);
		return pop3status::POP3_STATUS_OK;
	
		error:
			return pop3status::POP3_INVALID_PARAM;	
	}

	pop3status::Pop3Status
			Pop3Client::Pop3Connect()
	{
		POP3_CHECK_STATE(GREETING)

		int bytesRead = 0;
		sockStatus = sockMgr.SocketConnect(currentSettings.host, currentSettings.portNo);
		if(sockStatus != pop3socket::POP3_SOCKET_OK)
		{
			return MapSocketStatus(sockStatus);
		}

		sockStatus = sockMgr.SocketRead(POP3_BUFFER, pop3defaults::POP3_COMMAND_RESPONSE_SIZE, bytesRead);
		if(sockStatus != pop3socket::POP3_SOCKET_OK)
 		{
			return MapSocketStatus(sockStatus);
		}
		
		POP3_BUFFER[bytesRead] = '\0';
		apoprealm = POP3_BUFFER;
		pop3_trim(apoprealm, '<', '>', true);
		if(strcmp(POP3_BUFFER, apoprealm.c_str()) == 0)
		{
			apoprealm = "";
		}
		POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "Realm string = %s\n", apoprealm.c_str());

		POP3_SET_STATE(AUTHORIZATION);
		return pop3status::POP3_STATUS_OK;		
	}

	pop3status::Pop3Status
		Pop3Client::Pop3GetServerCapabilities(Pop3Capabilities& capabilities)
	{
		string command = pop3command::CAPA + " " + pop3defaults::POP3_CRLF;

		pop3status::Pop3Status capaStatus = NegotiatePop3Command(command);
		if(capaStatus != pop3status::POP3_STATUS_OK)
		{
			if(capaStatus == pop3status::POP3_INVALID_COMMAND)
			{
				POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Server does not support CAPA command\n");
				return pop3status::POP3_COMMAND_UNSUPPORTED;
			}
			return capaStatus;
		}

		Pop3Capabilities temp;
		map<string, string> capa_map;
		RetrieveList(capa_map, command, true);
		temp.parse_capability_reply(capa_map);
		capabilities = temp;
	
		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
			Pop3Client::Pop3StartTls()
	{
		POP3_CHECK_STATE(AUTHORIZATION)

		if(currentSettings.sslEnable != pop3ssl::POP3_START_TLS)
		{
			return pop3status::POP3_INVALID_STATE;
		}

		string command = pop3command::STLS + " " + pop3defaults::POP3_CRLF;

		pop3status::Pop3Status stlsStatus = NegotiatePop3Command(command);
		if(stlsStatus != pop3status::POP3_STATUS_OK)
		{
			if(stlsStatus == pop3status::POP3_INVALID_COMMAND)
			{
				return pop3status::POP3_STLS_UNSUPPORTED;
			}
			return stlsStatus;
		}
		
		pop3socket::POP3_SOCKET_STATUS_E stlsSocketStatus = sockMgr.SocketStartTls();
		if(stlsSocketStatus != pop3socket::POP3_SOCKET_OK)
		{
			return MapSocketStatus(stlsSocketStatus);
		}

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
			Pop3Client::Pop3Authenticate()
	{
		/* All validations are done in Init() except state */
		POP3_CHECK_STATE(AUTHORIZATION)

		if(apoprealm == "" && currentSettings.pop3Auth == pop3auth::APOP)
		{
			POP3_DEBUG_AUTH("No realm in server greeting. Cannot proceed for the current mech\n");
			return pop3status::POP3_AUTH_UNSUPPORTED;
		}

		pop3status::Pop3Status authStatus;
		string auth_str;		
		POP3_AUTH_STATE_E auth_state = POP3_AUTH_INIT;
		string mech_name, hostname;
		sockMgr.SocketGetHostName(hostname);

		Pop3AuthData_t auth_data = {currentSettings.pop3User, "",currentSettings.pop3Pass,hostname,"pop3",apoprealm};

		Pop3AuthModule* auth_module = Pop3AuthFactory::GetAuthModule(currentSettings.pop3Auth);
		if(auth_module == 0)
		{
			POP3_DEBUG_AUTH("Could not allocate memory for auth module\n");
			authStatus = pop3status::POP3_INTERNAL_ERROR;
			goto final;
		}

		auth_module->AuthMechName(mech_name);
		auth_state = auth_module->AuthStart(auth_data);

		if(auth_state == POP3_AUTH_ERROR)
		{
			POP3_DEBUG_AUTH("There was error while initiating auth module = %s\n", mech_name.c_str());
			authStatus = pop3status::POP3_AUTH_FAILED;
			goto end;
		}

		POP3_DEBUG_INFO2("Auth module %s started successfully\n", mech_name.c_str());

		if(auth_module->NeedsAuthCommand())
		{
			string command = "AUTH " + mech_name + "\r\n";
			authStatus = NegotiatePop3Command(command);
			if(authStatus != pop3status::POP3_STATUS_OK)
			{
				if(authStatus == pop3status::POP3_INVALID_COMMAND)
				{
					POP3_DEBUG_AUTH("%s mech not supported by server\n", mech_name.c_str());	
					authStatus = pop3status::POP3_AUTH_UNSUPPORTED;
					goto end;
				}
			}
			ParseAuthResponse(POP3_BUFFER, auth_str, false);
			pop3_remove_crlf(auth_str);
		}

		do
		{
			auth_state = auth_module->AuthStep(auth_str);
			string command = auth_str + "\r\n";
			authStatus = NegotiatePop3Command(command);
			if(authStatus != pop3status::POP3_STATUS_OK)
			{
				if(authStatus == pop3status::POP3_INVALID_COMMAND)
				{
					//Need a mechanism to check for USER/PASS sequence.
					//For others its auth failure
					authStatus = pop3status::POP3_AUTH_FAILED;
				}
				break;
			}
			ParseAuthResponse(POP3_BUFFER, auth_str, false);
			pop3_remove_crlf(auth_str);
		}while(auth_state != POP3_AUTH_END);

	end:
		auth_module->AuthEnd();
		delete auth_module;

	final:		
		if(authStatus == pop3status::POP3_STATUS_OK)
		{			
			POP3_SET_STATE(TRANSACTION);
		}

		return authStatus;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Stat(unsigned int& msgcount, unsigned int& totalsize)
	{
		POP3_CHECK_STATE(TRANSACTION)

		string command = pop3command::STAT + pop3defaults::POP3_CRLF;
	
		pop3status::Pop3Status statStatus = NegotiatePop3Command(command);
		if(statStatus != pop3status::POP3_STATUS_OK)
		{
			return statStatus;
		}

		StringTokenizer statToken(POP3_BUFFER, " ", "");
		vector<string> data;
		statToken.tokenize(data);

		if(data.size() < 3)
		{
			return pop3status::POP3_INVALID_RESPONSE;
		}

		pop3_remove_crlf(data[2]);

		pop3_string_to_type(data[1], msgcount);
		pop3_string_to_type(data[2], totalsize);

		POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "Stat response <%u> <%u>\n", msgcount, totalsize);
		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
			Pop3Client::Pop3List(map<unsigned int, unsigned int>& mail_list, unsigned int msg)
	{
		POP3_CHECK_STATE(TRANSACTION)

		string command = pop3command::LIST + " ";
		string msg_str;
		bool multi_line = true;
		if(msg)
		{
			pop3_type_to_string(msg, msg_str);
			command += msg_str;
			multi_line = false;
		}
		command += pop3defaults::POP3_CRLF;

		pop3status::Pop3Status list_status = RetrieveList<unsigned int, unsigned int>(mail_list, command, multi_line);
		if(list_status != pop3status::POP3_STATUS_OK)
		{
			if(list_status == pop3status::POP3_INVALID_COMMAND)
			{
				return pop3status::POP3_NOSUCH_MESSAGE;
			}

			return list_status;
		}

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3RetrieveTop(unsigned int msg_id, unsigned int n_lines, string& buffer)
	{
		POP3_CHECK_STATE(TRANSACTION)

		if(!msg_id)
		{
			return pop3status::POP3_INVALID_MID;
		}

		string mid_str, nline_str;
		pop3_type_to_string(msg_id, mid_str);
		pop3_type_to_string(n_lines, nline_str);

		string command = pop3command::TOP + " " + mid_str + " " + nline_str + pop3defaults::POP3_CRLF;

		pop3status::Pop3Status top_status = RetrieveMultiLine(command, buffer, true);

		if(top_status != pop3status::POP3_STATUS_OK)
		{
			if(top_status == pop3status::POP3_INVALID_COMMAND)
			{
				if(strcasestr(POP3_BUFFER, "message") != 0)
				{
					return pop3status::POP3_NOSUCH_MESSAGE;
				}
				else
				{
					return pop3status::POP3_COMMAND_UNSUPPORTED;
				}
			}

			return top_status;
		}

		size_t index = buffer.rfind(pop3defaults::POP3_MULTI_LINE_END.c_str());
		if(index != string::npos)
		{
			buffer = buffer.substr(0, index-1);
		}

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Retrieve(const unsigned int msg_id, const Pop3Callback& callback_t, const bool del)
	{
		POP3_CHECK_STATE(TRANSACTION)
	
		if(msg_id == 0)
		{
			return pop3status::POP3_INVALID_MID;
		}

		if(callback_t.retr_callback[0] == 0 || callback_t.retr_callback[1] == 0)
		{
			return pop3status::POP3_INVALID_PARAM;
		}

		string mid_str;
		pop3_type_to_string(msg_id, mid_str);
		string command = pop3command::RETR + " " + mid_str + pop3defaults::POP3_CRLF;

		pop3socket::POP3_SOCKET_STATUS_E status = sockMgr.SocketWrite(command.c_str(), command.length());

		if(status != pop3socket::POP3_SOCKET_OK)
		{
			return MapSocketStatus(status);
		}

		int bytesRead = 0;
		status = sockMgr.SocketRead(POP3_BUFFER, pop3defaults::POP3_COMMAND_RESPONSE_SIZE, bytesRead);

		if(status != pop3socket::POP3_SOCKET_OK)
		{
			return MapSocketStatus(status);
		}		

		POP3_BUFFER[bytesRead] = '\0';

		if(strcasestr(POP3_BUFFER, pop3defaults::POP3_OK_RESPONSE.c_str()) == 0)
		{
			return pop3status::POP3_NOSUCH_MESSAGE;
		}

		bool cont_retr = true;
		string temp = POP3_BUFFER;
		size_t index = 0;
		char* end = 0;
		pop3status::Pop3Status call_status = pop3status::POP3_STATUS_OK;

		if((index = temp.find(pop3defaults::POP3_CRLF)) != string::npos)
		{
			unsigned int offset = 2;
			if(temp.find(pop3defaults::POP3_MULTI_LINE_END.c_str()) != string::npos)
			{
				offset = 5;
				cont_retr = false;
			}

			call_status = callback_t.retr_callback[0](callback_t.context, &POP3_BUFFER[index+2], bytesRead-index-offset, msg_id);
			if(call_status != pop3status::POP3_STATUS_OK)
			{
				if(cont_retr)
				{
					callback_t.retr_callback[1](callback_t.context, 0, 0, msg_id);
					return call_status;
				}
			}

			if(cont_retr == false)
			{
				callback_t.retr_callback[1](callback_t.context, 0, 0, msg_id);
				goto finish;
			}
		}
			
		bytesRead = pop3defaults::POP3_COMMAND_RESPONSE_SIZE;
		while(bytesRead > 0)
		{
			status = sockMgr.SocketRead(POP3_BUFFER, pop3defaults::POP3_COMMAND_RESPONSE_SIZE, bytesRead);	
			if(status != pop3socket::POP3_SOCKET_OK)
			{
				callback_t.retr_callback[1](callback_t.context, 0, 0, msg_id);
				return MapSocketStatus(status);
			}

			if((end = strcasestr(POP3_BUFFER, pop3defaults::POP3_MULTI_LINE_END.c_str())) != 0)
			{
				//write last chunk
				*end = '\0';
				call_status = callback_t.retr_callback[1](callback_t.context, POP3_BUFFER, strlen(POP3_BUFFER), msg_id);

				if(call_status != pop3status::POP3_STATUS_OK)
				{
					goto error;
				}
				
				goto finish;
			}

			call_status = callback_t.retr_callback[0](callback_t.context, POP3_BUFFER, bytesRead, msg_id);
			
			if(call_status != pop3status::POP3_STATUS_OK)
			{
				callback_t.retr_callback[1](callback_t.context, 0, 0, msg_id);
				goto error;
			}			
		}

error:
		return call_status;

finish:
		if(del)
			return Pop3Delete(msg_id);

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Retrieve(const unsigned int msg_id, const string& retr_path, const bool del)
	{
		int fd = open(retr_path.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0644);
		if(fd == -1)
		{
			int err = errno;
			POP3_DEBUG_INTERNAL("File error occured = %s\n", strerror(err));
			return pop3status::POP3_FILE_ERROR;
		}

		Pop3Callback retr_callback_t;		
		retr_callback_t.context = &fd;
		retr_callback_t.retr_callback[0] = RetrCallbackBegin;
		retr_callback_t.retr_callback[1] = RetrCallbackEnd;
		return Pop3Retrieve(msg_id, retr_callback_t, del);
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Delete(const unsigned int msg_id)
	{
		POP3_CHECK_STATE(TRANSACTION)

		if(msg_id == 0)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_WARN, "Invalid Message-Id specified for DELE\n");
			return pop3status::POP3_INVALID_MID;
		}

		string mid_str;
		pop3_type_to_string(msg_id, mid_str);
		string command = pop3command::DELE + " " + mid_str + pop3defaults::POP3_CRLF;

		pop3status::Pop3Status deleStatus = NegotiatePop3Command(command);

		if(deleStatus != pop3status::POP3_STATUS_OK)
		{
			if(deleStatus == pop3status::POP3_INVALID_COMMAND)
			{
				return pop3status::POP3_NOSUCH_MESSAGE;
			}

			return deleStatus;
		}

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Reset()
	{
		POP3_CHECK_STATE(TRANSACTION)

		string command = pop3command::RSET + pop3defaults::POP3_CRLF;

		pop3status::Pop3Status rsetStatus = NegotiatePop3Command(command);
		if(rsetStatus != pop3status::POP3_STATUS_OK)
		{
			if(rsetStatus != pop3status::POP3_INVALID_COMMAND)
			{
				return rsetStatus;
			}
			return pop3status::POP3_INVALID_RESPONSE;
		}

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Noop()
	{
		POP3_CHECK_STATE(TRANSACTION)

		string command = pop3command::NOOP + pop3defaults::POP3_CRLF;

		pop3status::Pop3Status rsetStatus = NegotiatePop3Command(command);
		if(rsetStatus != pop3status::POP3_STATUS_OK)
		{
			if(rsetStatus != pop3status::POP3_INVALID_COMMAND)
			{
				return rsetStatus;
			}
			return pop3status::POP3_INVALID_RESPONSE;
		}

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Quit()
	{		
		string command = pop3command::QUIT + pop3defaults::POP3_CRLF;

		pop3status::Pop3Status quitStatus = NegotiatePop3Command(command);
		if(quitStatus != pop3status::POP3_STATUS_OK)
		{
			//POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, "Disconnect failed\n");
			//return pop3status::POP3_CONNECTION_FAIL;
		}

		Pop3Disconnect();
		
		POP3_SET_STATE(UPDATE);
		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3Disconnect()
	{
		sockMgr.SocketDisconnect();
		POP3_SET_STATE(GREETING);

		POP3_DEBUG(pop3debug::POP3_DEBUG_INFO2, "Disconnected socket connection\n");

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::Pop3UniqueIdList(map<unsigned int, string>& uid_list, const unsigned int msg_id)
	{
		POP3_CHECK_STATE(TRANSACTION)

		string command = pop3command::UIDL + " ";
		string msg_str;
		bool multi_line = true;
		if(msg_id)
		{
			pop3_type_to_string(msg_id, msg_str);
			command += msg_str;
			multi_line = false;
		}
		command += pop3defaults::POP3_CRLF;

		pop3status::Pop3Status uidl_status = RetrieveList<unsigned int, string>(uid_list, command, multi_line);
		if(uidl_status != pop3status::POP3_STATUS_OK)
		{
			if(uidl_status == pop3status::POP3_INVALID_COMMAND)
			{
				// Just a guess.
				if(msg_id && strcasestr(POP3_BUFFER, "message") != 0)
				{
					return pop3status::POP3_INVALID_MID;
				}
				
				return pop3status::POP3_COMMAND_UNSUPPORTED;
			}

			return uidl_status;
		}

		return pop3status::POP3_STATUS_OK;
	}

	/* Private Interfaces */
	pop3status::Pop3Status 
			Pop3Client::MapSocketStatus(pop3socket::POP3_SOCKET_STATUS_E socket_status)
	{
		switch(socket_status)
		{
			case pop3socket::POP3_SOCKET_INTERNAL:
				return pop3status::POP3_INTERNAL_ERROR;

			case pop3socket::POP3_SOCKET_TIMEOUT:
				return pop3status::POP3_CONNECTION_TIMEOUT;

			case pop3socket::POP3_SOCKET_FAIL:
				return pop3status::POP3_CONNECTION_FAIL;
	
			case pop3socket::POP3_SOCKET_UNSUPPORTED:
				return pop3status::POP3_PROTOCOL_UNSUPPORTED;

			case pop3socket::POP3_SOCKET_SERV_UNSUPPORTED:
				return pop3status::POP3_NO_SERVER;

			case pop3socket::POP3_SOCKET_CONN_RESET:
			case pop3socket::POP3_SOCKET_NOT_CONNECTED:
			case pop3socket::POP3_SOCKET_HOST_ERROR:
			case pop3socket::POP3_SOCKET_CONN_CLOSED:
				return pop3status::POP3_CONNECTION_FAIL;

			case pop3socket::POP3_SOCKET_SSL_UNSUPPORTED:
				return pop3status::POP3_SSL_UNSUPPORTED;

			case pop3socket::POP3_SOCKET_SSL_HANDSHAKE_FAIL:
			case pop3socket::POP3_SOCKET_CERT_VERIFY_FAIL:
				return pop3status::POP3_SSL_HANDSHAKE_FAIL;

			case pop3socket::POP3_SOCKET_SSL_NO_CA:
				return pop3status::POP3_SSL_HANDSHAKE_FAIL;

			default:
				return pop3status::POP3_STATUS_OK;
		}
	}

	pop3status::Pop3Status
			Pop3Client::NegotiatePop3Command(const string& command)
	{
		pop3socket::POP3_SOCKET_STATUS_E status = sockMgr.SocketWrite(command.c_str(), command.length());

		if(status != pop3socket::POP3_SOCKET_OK)
		{
			Pop3Disconnect();
			return MapSocketStatus(status);
		}

		bytes_read = 0;
		uint16_t offset = 0;
		memset(POP3_BUFFER, '\0', pop3defaults::POP3_COMMAND_RESPONSE_SIZE);

		while(true)
		{
			status = sockMgr.SocketRead(POP3_BUFFER + offset, pop3defaults::POP3_COMMAND_RESPONSE_SIZE, bytes_read);
			offset += bytes_read;

			if(status != pop3socket::POP3_SOCKET_OK)
			{
				Pop3Disconnect();
				return MapSocketStatus(status);
			}		

			POP3_BUFFER[offset] = '\0';

			if(strcasestr(POP3_BUFFER, pop3defaults::POP3_CRLF.c_str()) != 0 || bytes_read == 0)
			{
				break;
			}
		}

		if(strcasestr(POP3_BUFFER, pop3defaults::POP3_OK_RESPONSE.c_str()) != 0)
		{
			return pop3status::POP3_STATUS_OK;
		}

		return pop3status::POP3_INVALID_COMMAND;
	}
	
	template<typename T1, typename T2> pop3status::Pop3Status
		Pop3Client::RetrieveList(map<T1, T2>& uid_list, const string& command, const bool multi_line)
	{
		string temp;
		pop3status::Pop3Status retr_status = RetrieveMultiLine(command, temp, multi_line);
		if(retr_status != pop3status::POP3_STATUS_OK)
		{
			return retr_status;
		}
		
		StringTokenizer tokenizer(temp, pop3defaults::POP3_CRLF,".");
		//cout<<"TEMP : "<<temp << " "<<temp.length()<<endl;

		while(tokenizer.has_more_tokens())
		{
			string data;
			T1 value1;
			T2 value2;

			tokenizer.next_token(data);

			pop3_break_string2<T1, T2>(data, value1, value2, ' ');
			uid_list.insert(pair<T1, T2>(value1, value2));
			//cout<<data<<endl;
			cout<<"<"<<value1<<"> "<<"<"<<value2<<">"<<endl;			
		}

		return pop3status::POP3_STATUS_OK;
	}

	pop3status::Pop3Status
		Pop3Client::RetrieveMultiLine(const string& command, string& response, const bool multi_line)
	{
		pop3status::Pop3Status mline_status = NegotiatePop3Command(command);

		if(mline_status != pop3status::POP3_STATUS_OK)
		{
			return mline_status;
		}

		int bytesRead = GetBytesRead();

		string temp = POP3_BUFFER;
		bool finish = false;
		size_t index = 0;

		if((index = temp.find(pop3defaults::POP3_CRLF)) != string::npos)
		{
			if(!multi_line)
			{
				if((index = temp.find_first_of(" ")) != string::npos)
				{
					temp = temp.substr(index + 1, bytesRead - index -1);
				}
				finish = true;
			}
			else
			{
				if(strcasestr(POP3_BUFFER, pop3defaults::POP3_MULTI_LINE_END.c_str()) != 0)
				{
					finish = true;
				}
				temp.assign(&POP3_BUFFER[index+2], bytesRead-index-2);
			}
		}		
	
		if(!finish)
		{
			bytesRead = pop3defaults::POP3_COMMAND_RESPONSE_SIZE;
			while(bytesRead > 0)
			{
				pop3socket::POP3_SOCKET_STATUS_E status = sockMgr.SocketRead(POP3_BUFFER, pop3defaults::POP3_COMMAND_RESPONSE_SIZE, bytesRead);	
				if(status != pop3socket::POP3_SOCKET_OK)
				{
					return MapSocketStatus(status);
				}

				if(strcasestr(POP3_BUFFER, pop3defaults::POP3_MULTI_LINE_END.c_str()) != 0)
				{
					temp.append(POP3_BUFFER, bytesRead);
					break;
				}
				temp.append(POP3_BUFFER, bytesRead);
			}

			response = temp;
		}
		return pop3status::POP3_STATUS_OK;
	}

	void
		Pop3Client::ParseAuthResponse(const char* response, string& output, const bool base64decode)
	{
		const char* str;
		POP3_DEBUG_INFO2("ParseAuthResponse : %s\n", response);
		if((str = strstr(response, " ")) != 0)
        {
            output = str + 1;
            pop3_remove_crlf(output);
			//cout<<"ParseAuthResponse : "<<output<<endl;
			if(base64decode)
			{
				string decode;
				//AuthManager::SASL_Login_decode(output, decode);
				output = decode;
			}
        }
	}

	bool
		Pop3Client::GetServerReplyString(string& server_reply)
	{
		string value1, value2;	
		pop3_break_string2(POP3_BUFFER, value1, value2, ' ');

		server_reply = value2;
		if(strcasestr(value1.c_str(), pop3defaults::POP3_OK_RESPONSE.c_str()) != 0)
		{
			return true;
		}
		
		return false;
	}
}
