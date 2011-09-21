#include "pop3commons.h"
#include "pop3attrs.h"

#ifndef __POP3DEFS__H__
#define __POP3DEFS__H__

#define DECL_CONST_STRING(type, name, value)\
		const type name = #value;

#define DECL_CONST(type, name, value)\
		const type name = value;

#define POP3_SOCKET_BUFFER 65536


namespace pop3
{

	typedef UINT16 Pop3Port;

	const string pop3_status_string[] =
	{
		"The operation completed successfully",
		"S: Connection to specified POP3 Server failed",
		"C: Connection to specified POP3 Server timed out",
		"C: The protocol (IPv4 or IPv6) is not supported by the underlying OS",
		"S: The server does not support POP3 protocol in specified port",
		"S: The server does not support POP3 protocl with SSL in specified port",
		"S: The SSL/TLS handshake failed with the server",
		"S: The POP3 server does not support STARTLS mode",
		"S: Authentication to POP3 server failed",
		"S: Authentication method is not supported by the server",
		"S: The Pop3 Command is unsupported by the server",
		"S: The current mailbox is locked by the POP3 server. Need to try after sometime",
		"S: Invalid response is sent by the POP3 server",
		"S: The Server does not have mail with specified message id",
		"C: Invalid message-id is specified for the current operation",
		"S: The Pop3 Command is unsupported (OR returned with negative response) by the server",
		"C: Invalid Authentication setting provided",
		"C: Current operation requested does not fit into the client's internal state",
		"C: One or more parameter(s) supplied is/are invalid",
		"C: Disk full occured during disk write operation",
		"C: File I/O error occured",
		"C: Internal occured in the pop3client"
	};

	namespace pop3defaults
	{
		DECL_CONST(UINT16, POP3_SERVER_PORT, 110)
		DECL_CONST(UINT16, POP3_SSL_PORT, 995)	
		DECL_CONST(UINT, POP3_DEFAULT_TIMEOUT, 30);
		DECL_CONST(UINT, POP3_COMMAND_RESPONSE_SIZE, 1024);
		DECL_CONST_STRING(string, POP3_OK_RESPONSE, +)
		DECL_CONST_STRING(string, POP3_ERR_RESPONSE, -)
		DECL_CONST_STRING(string, POP3_CRLF, \r\n);
		DECL_CONST_STRING(string, POP3_MULTI_LINE_END, \r\n.\r\n);
		DECL_CONST_STRING(string, POP3_EXT_IN_USE, IN-USE);
		DECL_CONST_STRING(string, SASL_PLAIN_STR, PLAIN);
		DECL_CONST_STRING(string, SASL_LOGIN_STR, LOGIN);
		DECL_CONST_STRING(string, SASL_CRAM_MD5_STR, CRAM-MD5);
		DECL_CONST_STRING(string, SASL_DIGEST_MD5_STR, DIGEST-MD5);
		DECL_CONST_STRING(string, SASL_NTLM_STR, NTLM);
		DECL_CONST_STRING(string, SASL_GSSAPI_STR, GSSAPI);
		DECL_CONST_STRING(string, SASL_ANONYMOUS_STR, ANONYMOUS);
		DECL_CONST_STRING(string, SSL_CA_PATH, /etc/ssl/certs);
	}

	namespace pop3command
	{
		DECL_CONST_STRING(string, USER, USER)
		DECL_CONST_STRING(string, PASS, PASS)
		DECL_CONST_STRING(string, APOP, APOP)
		DECL_CONST_STRING(string, AUTH, AUTH)
		DECL_CONST_STRING(string, STAT, STAT)
		DECL_CONST_STRING(string, LIST, LIST)
		DECL_CONST_STRING(string, RETR, RETR)
		DECL_CONST_STRING(string, DELE, DELE)
		DECL_CONST_STRING(string, NOOP, NOOP)
		DECL_CONST_STRING(string, RSET, RSET)
		DECL_CONST_STRING(string, QUIT, QUIT)
		DECL_CONST_STRING(string, UIDL, UIDL)
		DECL_CONST_STRING(string, TOP, TOP)
		DECL_CONST_STRING(string, CAPA, CAPA)
		DECL_CONST_STRING(string, STLS, STLS)
	}

    namespace pop3socket
    {
        typedef enum
        {
            POP3_SOCKET_OK,
            POP3_SOCKET_INTERNAL,
            POP3_SOCKET_TIMEOUT,
            POP3_SOCKET_FAIL,
            POP3_SOCKET_UNSUPPORTED,
            POP3_SOCKET_SERV_UNSUPPORTED,
            POP3_SOCKET_CONN_RESET,
			POP3_SOCKET_CONN_CLOSED,
            POP3_SOCKET_NOT_CONNECTED,
            POP3_SOCKET_HOST_ERROR,
            POP3_SOCKET_SSL_UNSUPPORTED,
            POP3_SOCKET_SSL_HANDSHAKE_FAIL,
            POP3_SOCKET_CERT_VERIFY_FAIL,
            POP3_SOCKET_SSL_NO_CA
        }POP3_SOCKET_STATUS_E;
    }

	namespace pop3auth
    {
		typedef enum
		{
			POP3,
			APOP = 2,
			SASL_PLAIN,
			SASL_LOGIN,
			SASL_CRAM_MD5,
			SASL_DIGEST_MD5,
			SASL_NTLM,
			SASL_GSSAPI,
			SASL_ANONYMOUS = 1
		}POP3_AUTH_TYPE_E;
	}
}

#endif
