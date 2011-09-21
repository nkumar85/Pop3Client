#include "pop3authfactory.h"

namespace pop3
{
	Pop3AuthModule::~Pop3AuthModule(){}
	Pop3AuthModule* Pop3AuthFactory::GetAuthModule(pop3auth::POP3_AUTH_TYPE_E auth_type)
	{
		switch(auth_type)
		{
			using namespace pop3auth;

			case POP3:
				return new Pop3ClearMech();
				break;
		
			case APOP:
				return new Pop3ApopMech();
				break;

			case SASL_ANONYMOUS:
				return new Pop3AnonymousMech();
				break;

			case SASL_PLAIN:
				return new Pop3PlainMech();
				break;

			case SASL_LOGIN:
				return new Pop3LoginMech();
				break;

			case SASL_CRAM_MD5:
				return new Pop3CramMd5Mech();
				break;

			case SASL_DIGEST_MD5:
				return new Pop3DigestMd5Mech();
				break;

			case SASL_NTLM:
				return new Pop3NtlmMech();
				break;

			case SASL_GSSAPI:
				return new Pop3GssapiMech();
				break;

			default:
				return 0;
				break;
		}
	}	
}
