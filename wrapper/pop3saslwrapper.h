/*

LIBRARY COPYRIGHT:

* Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
	
* CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
* THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
* AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
* FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
* AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
* OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

WRAPPER:

	SASL C++ wrapper for cyrus project.
	Copyright (c) 2011 Heramba
	mail: heramba85@gmail.com
*/


#include "common/pop3commons.h"
#include "debug/pop3debug.h"

#include<sasl/sasl.h>
#include<sasl/saslutil.h>

#ifndef __POP3__SASL__MGR
#define __POP3__SASL__MGR

#define POP3_SASL_DEBUG(fmt,...)\
	POP3_DEBUG(pop3debug::POP3_DEBUG_AUTH, "%s : "fmt, sasl_errdetail(conn), ##__VA_ARGS__)

#define POP3_NTLM_MECH "NTLM"
#define POP3_GSSAPI_MECH "GSSAPI"
#define POP3_SVC_POP3 "pop3"
#define POP3_SVC_POP "pop"
#define POP3_SVC_POPSVC "pop3svc"

namespace pop3
{
	typedef struct Pop3SaslInfo
	{
		string user_name;
		string user_pass;
		string realm;
		string service;
		string mech;
		string hostname;
	}Pop3SaslInfo_t;

	typedef enum POP3_SASL_STATE
	{
		POP3_SASL_ERROR = -1,
		POP3_SASL_OK
	}POP3_SASL_STATE_E;

	class Pop3SaslWrapper
	{		
		//sasl callbacks
		friend int getauthname_func(void *context, int id, const char **result, unsigned *len);
		friend int getsecret_func(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret);
		//friend int getrealm_func(void *context, int id, const char **availrealms, const char **result);
		friend int getcannonical_user_func(sasl_conn_t *conn, void *context, const char *in, unsigned inlen,  unsigned flags,
                const char *user_realm, char *out, unsigned out_max, unsigned *out_len);

		private:
			sasl_callback_t sasl_callback[5];
			sasl_secret_t* secret;
			sasl_conn_t* conn;
			sasl_interact_t *client_interact;
			sasl_security_properties_t secprops;

			Pop3SaslInfo_t sasl_data;
			bool init;

		public:
			Pop3SaslWrapper() : secret(0), conn(0), client_interact(0), init(false){}
			POP3_SASL_STATE_E warn_unchecked_return SaslInit(const Pop3SaslInfo_t& sasl_data);
			POP3_SASL_STATE_E warn_unchecked_return SaslStep(string& auth_str);
			void SaslDispose();
			~Pop3SaslWrapper();
	};
}

#endif
