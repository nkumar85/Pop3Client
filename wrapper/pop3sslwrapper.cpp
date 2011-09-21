#include "pop3sslwrapper.h"

namespace pop3
{
	pop3socket::POP3_SOCKET_STATUS_E 
			SSLWrapper::SSLInit()
	{
		SSL_library_init();
		OpenSSL_add_all_algorithms();
		SSL_load_error_strings();

		method = const_cast<SSL_METHOD*>(SSLv23_client_method());
		ctx = SSL_CTX_new(method);
		if(ctx == 0)
		{  
			POP3_DEBUG(pop3debug::POP3_DEBUG_INTERNAL, "SSL Context allocation failed\n");
			return pop3socket::POP3_SOCKET_INTERNAL;
		}
		ssl = SSL_new(ctx);
		if(ssl == 0)
		{			
			POP3_DEBUG(pop3debug::POP3_DEBUG_INTERNAL, "SSL allocation failed\n");
			return pop3socket::POP3_SOCKET_INTERNAL;
		}

		return pop3socket::POP3_SOCKET_OK;
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SSLWrapper::SSLConnect(int fd, int sslVerifyType, const string& ca_path, const string& ca_client_cert, const string& cn)
	{
		if(SSLInit() != pop3socket::POP3_SOCKET_OK)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_INTERNAL, "SSL Initialization failed\n");
			return pop3socket::POP3_SOCKET_FAIL;
		}

		//Attach  existing connected socket descriptor to SSL library
		SSL_set_fd(ssl, fd);

		//Set verification type
		if(sslVerifyType == 0)
		{			
			//No CA verification
			SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
		}
		else
		{
			// CA verification
			SSL_CTX_load_verify_locations(ctx, NULL, ca_path.c_str());
			SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER, NULL);
		}

		//Client verification
		if(ca_client_cert != "")
		{
			STACK_OF(X509_NAME) *ca_cert_list = SSL_load_client_CA_file(ca_client_cert.c_str());
			if(ca_cert_list)
			{
				SSL_CTX_set_client_CA_list(ctx, ca_cert_list);
			}
		}

		int ssl_conn = SSL_connect(ssl);
		if(ssl_conn != 1)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, "SSL_Connect failed with result = %d\n", ssl_conn);
			return pop3socket::POP3_SOCKET_SSL_HANDSHAKE_FAIL;
		}

		POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "SSL_Connect pass with result = %d\n", ssl_conn);

		//Need to check common name
		int ssl_result = SSL_get_verify_result(ssl);

		POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "SSL_get_verify_result result = %d\n", ssl_result);

		//Certificate negotiation
		X509 *certificate = SSL_get_peer_certificate(ssl);

		switch(ssl_result)
		{
			case X509_V_OK:
			{
				char common_name [512] = {0};
				X509_NAME* name = X509_get_subject_name(certificate);
				X509_NAME_get_text_by_NID(name, NID_commonName, common_name, 512);
				POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "Certificate common name = %s\n", common_name);
				if(sslVerifyType)
				{
					if(strcmp(cn.c_str(), common_name) == 0)
					{
						return pop3socket::POP3_SOCKET_OK; 
					}
					return pop3socket::POP3_SOCKET_SSL_HANDSHAKE_FAIL;
				}
			}

			case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			{
				POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "Found Self signed cert\n");
				if(sslVerifyType == 0)
				{
					return pop3socket::POP3_SOCKET_OK;
				}
				return pop3socket::POP3_SOCKET_SSL_HANDSHAKE_FAIL;
			}

			default:
				return pop3socket::POP3_SOCKET_SSL_HANDSHAKE_FAIL;
		}
	}

	pop3socket::POP3_SOCKET_STATUS_E 
			SSLWrapper::SSLRead(char* buffer, const size_t bufSize, int& bytesRead)
	{
		if(ssl)
		bytesRead = SSL_read(ssl, buffer, bufSize);
		return MapSSLError(bytesRead);
	}
	
	pop3socket::POP3_SOCKET_STATUS_E 
			SSLWrapper::SSLWrite(const char* data, const size_t sendLen)
	{	
		int bytesRead = 0;
		if(ssl)	
		bytesRead = SSL_write(ssl, data, sendLen);
		return MapSSLError(bytesRead);
	}

	pop3socket::POP3_SOCKET_STATUS_E
			SSLWrapper::SSLDisconnect()
	{		
		if(ssl)
		{
			/* 
				Since we send 'close notify' to server, we will have to do ssl_shutdown twice to have bidirectional closure.
				See NOTES section of http://www.openssl.org/docs/ssl/SSL_shutdown.html
			*/
			if(SSL_shutdown(ssl) == 0)
			{
				switch (SSL_get_shutdown(ssl))
				{
					case SSL_SENT_SHUTDOWN:
					{
						SSL_shutdown(ssl);
						break;
					}

				    default:
						break;
		    	}
			}

			SSL_free(ssl);
			ssl = 0;
		}

		if(ctx)
		{
			SSL_CTX_free(ctx);
			ctx = 0;
		}

		return pop3socket::POP3_SOCKET_OK;
	}

	pop3socket::POP3_SOCKET_STATUS_E
		SSLWrapper::MapSSLError(int ret_val)
	{
		if(ssl == 0)
		{
			return pop3socket::POP3_SOCKET_FAIL;
		}

		int ret = SSL_get_error(ssl, ret_val);

		switch(ret)
		{
			case SSL_ERROR_NONE:
				return pop3socket::POP3_SOCKET_OK;

			case SSL_ERROR_ZERO_RETURN:
			case SSL_ERROR_WANT_CONNECT:
				return pop3socket::POP3_SOCKET_NOT_CONNECTED;

			case SSL_ERROR_WANT_X509_LOOKUP:

			case SSL_ERROR_SYSCALL:
				return pop3socket::POP3_SOCKET_INTERNAL;
	
			case SSL_ERROR_SSL:
			default:
				return pop3socket::POP3_SOCKET_FAIL;
		}
	}
}
