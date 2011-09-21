/*

* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
* THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.


	* SSL C++ wrapper for OpenSSL library 
	* Copyright (c) 2011 heramba(heramba85@gmail.com)
*/

#include "common/pop3commons.h"
#include "debug/pop3debug.h"
#include "common/pop3defs.h"

// OpenSSL library include for SSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef __POP3_SSL__WRAPPER
#define __POP3_SSL__WRAPPER

namespace pop3
{
	class SSLWrapper
	{
		private:
			//Openssl initializations
            
			SSL_CTX* ctx;
			SSL* ssl;
			SSL_METHOD *method;

			SSLWrapper():ctx(0), ssl(0), method(0){}
			pop3socket::POP3_SOCKET_STATUS_E warn_unchecked_return SSLInit();
			pop3socket::POP3_SOCKET_STATUS_E warn_unchecked_return SSLConnect(int fd = -1, int sslVerifyType = 0, const string& ca_path = "", 
													const string& ca_client_cert = "", const string& cn = "");
			pop3socket::POP3_SOCKET_STATUS_E warn_unchecked_return SSLRead(char* buffer, const size_t bufSize, int& bytesRead);
			pop3socket::POP3_SOCKET_STATUS_E warn_unchecked_return SSLWrite(const char* data, const size_t sendLen);
			pop3socket::POP3_SOCKET_STATUS_E SSLDisconnect();
			pop3socket::POP3_SOCKET_STATUS_E MapSSLError(int ret);

			friend class SocketManager;
	};
}

#endif
