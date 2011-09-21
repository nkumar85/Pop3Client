#include <common/pop3defs.h>
#include <sock/pop3sockmanager.h>
#include "pop3capabilities.h"
#include <auth/pop3authfactory.h>
#if 0
#include "pop3utils.h"
#include "pop3strtoken.h"
#include "pop3digestmd5.h"
#include "pop3saslmanager.h"
#endif

#ifndef __POP3__CLIENT__H
#define __POP3__CLIENT__H

#define POP3_CHECK_STATE(x)\
		if(current_state != pop3state::x) { return pop3status::POP3_INVALID_STATE;}

#define POP3_SET_STATE(x)\
		current_state = pop3state::x;

namespace pop3
{
	namespace pop3state
    {
        typedef enum
        {
			INIT,
            GREETING,
            AUTHORIZATION,
            TRANSACTION,
            UPDATE
        }Pop3State;
    }

	namespace pop3status
    {
        typedef enum
        {
            POP3_STATUS_OK,
            POP3_CONNECTION_FAIL,
            POP3_CONNECTION_TIMEOUT,
			POP3_PROTOCOL_UNSUPPORTED,
			POP3_NO_SERVER,
            POP3_SSL_UNSUPPORTED,
            POP3_SSL_HANDSHAKE_FAIL,
			POP3_STLS_UNSUPPORTED,
            POP3_AUTH_FAILED,
			POP3_AUTH_UNSUPPORTED,
            POP3_COMMAND_UNSUPPORTED,
			POP3_MAILBOX_LOCKED,
			POP3_INVALID_RESPONSE,
			POP3_NOSUCH_MESSAGE,
            POP3_INVALID_MID,
            POP3_INVALID_COMMAND,
            POP3_INVALID_AUTH,
            POP3_INVALID_STATE,
			POP3_INVALID_PARAM,
			POP3_DISK_FULL,
			POP3_FILE_ERROR,
            POP3_INTERNAL_ERROR
        }Pop3Status;
    }

	typedef struct
	{
		string host;
		Pop3Port portNo;
		pop3ssl::Pop3Ssl sslEnable;
		pop3verifytype::Pop3VerifyType sslVerifyType;
		pop3auth::POP3_AUTH_TYPE_E pop3Auth;
		unsigned int timeout;
		string pop3User;
		string pop3Pass;
		string ca_path;
		string ca_client_cert;
	}Pop3Params;

	typedef pop3status::Pop3Status (*pop3_callback_t)(void* context, void* data, size_t data_size, unsigned int mail_index);

	typedef struct Pop3Callback_t
	{
		void* context;
		pop3_callback_t retr_callback[2];

		Pop3Callback_t()
		{
			context = 0;
			retr_callback[0] = retr_callback[1] = 0;
		}

	}Pop3Callback;

	class Pop3Client
	{
		friend pop3status::Pop3Status RetrCallbackBegin(void* context, void* data, size_t data_size, unsigned int mail_index);
		friend pop3status::Pop3Status RetrCallbackEnd(void* context, void* data, size_t data_size, unsigned int mail_index);

		private:
			pop3state::Pop3State current_state;
			string apoprealm;
			pop3socket::POP3_SOCKET_STATUS_E sockStatus;
			Pop3Params currentSettings;
			SocketManager sockMgr;
			pop3status::Pop3Status MapSocketStatus(pop3socket::POP3_SOCKET_STATUS_E);
#if 0
			pop3status::Pop3Status NegotiatePop3Auth();
			pop3status::Pop3Status NegotiateApopAuth();
			pop3status::Pop3Status NegotiatePlainAuth(const string& mech);
			pop3status::Pop3Status NegotiateLoginAuth();
			pop3status::Pop3Status NegotiateCramMd5Auth();
			pop3status::Pop3Status NegotiateDigestMd5Auth();
			pop3status::Pop3Status NegotiateNtlmAuth();
			pop3status::Pop3Status NegotiateKerberosAuth();
			pop3status::Pop3Status NegotiateAnonymousAuth();
#endif
			pop3status::Pop3Status NegotiatePop3Command(const string& command);			
			template<typename T1, typename T2>
			pop3status::Pop3Status RetrieveList(map<T1, T2>& uid_list, const string& command, const bool multi_line = true);
			pop3status::Pop3Status RetrieveMultiLine(const string& command, string& response, const bool multi_line = true);
			int GetBytesRead() { return bytes_read; }
			void ParseAuthResponse(const char* response, string& output, const bool base64decode = true);
			char POP3_BUFFER[pop3defaults::POP3_COMMAND_RESPONSE_SIZE];
			int bytes_read;

		public:
			Pop3Client(const Pop3Params& pop3Params) : current_state(pop3state::INIT), apoprealm(""), currentSettings(pop3Params),
				sockMgr(currentSettings.timeout,
						currentSettings.sslEnable,
						currentSettings.sslVerifyType,
						currentSettings.ca_path,
						currentSettings.ca_client_cert
						),
						bytes_read(0)
			{}

			pop3status::Pop3Status warn_unchecked_return Pop3Init();
			pop3status::Pop3Status warn_unchecked_return Pop3Connect();
			pop3status::Pop3Status warn_unchecked_return Pop3GetServerCapabilities(Pop3Capabilities& capabilities);
			pop3status::Pop3Status warn_unchecked_return Pop3GetSASLCapabilities(vector<string>& mechanisms);
			pop3status::Pop3Status warn_unchecked_return Pop3StartTls();
			pop3status::Pop3Status warn_unchecked_return Pop3Authenticate();
			pop3status::Pop3Status warn_unchecked_return Pop3Stat(unsigned int& msg_count, unsigned int& total_size);
			pop3status::Pop3Status warn_unchecked_return Pop3List(map<unsigned int, unsigned int>& mail_list, unsigned int msg_id = 0);
			pop3status::Pop3Status warn_unchecked_return Pop3RetrieveTop(unsigned int msg_id, unsigned int n_lines, string& buffer);
			pop3status::Pop3Status warn_unchecked_return Pop3Retrieve(const unsigned int msg_id, const string& retr_path, const bool del = false);
			pop3status::Pop3Status warn_unchecked_return Pop3Retrieve(const unsigned int msg_id, const Pop3Callback& callback_t, const bool del = false);
			pop3status::Pop3Status warn_unchecked_return Pop3Delete(const unsigned int msg_id);
			pop3status::Pop3Status warn_unchecked_return Pop3Reset();
			pop3status::Pop3Status warn_unchecked_return Pop3Noop();
			pop3status::Pop3Status warn_unchecked_return Pop3UniqueIdList(map<unsigned int, string>& uid_list, const unsigned int msg_id = 0);
			pop3status::Pop3Status Pop3Quit();
			pop3status::Pop3Status Pop3Disconnect();
			bool IsAuthorized() const { return current_state > pop3state::AUTHORIZATION; }
			//Temporarily made public
			bool GetServerReplyString(string& server_reply);
			void Pop3GetErrorDescription(const pop3status::Pop3Status pop3_status, string& reply) const
			{ reply = pop3_status_string[pop3_status];}
	};

}

#endif
