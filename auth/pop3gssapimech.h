#include "pop3authmodule.h"
#include "pop3authcommon.h"
#include <wrapper/pop3saslwrapper.h>
#include <wrapper/pop3krb5wrapper.h>

#ifndef __POP3__GSSAPI__AUTH__H
#define __POP3__GSSAPI__AUTH__H

namespace pop3
{
	class Pop3GssapiMech : public Pop3AuthModule
	{
		POP3_AUTH_STATE_E auth_state;
		const string mech_name;
		int step_count;
		Pop3AuthData_t auth_data;
		Pop3SaslWrapper sasl_gssapi;
		Pop3Krb5Wrapper krb5_inst;
		Pop3Krb5CtxData_t krb5_data;

		protected:
			UINT8 AuthStepCount() const 
			{
				return 3;
			}

		public:
			Pop3GssapiMech() : auth_state(POP3_AUTH_INIT), mech_name("GSSAPI")
			{
				step_count = AuthStepCount();
			}
			POP3_AUTH_STATE_E AuthStart(const Pop3AuthData_t& auth_data);
			POP3_AUTH_STATE_E AuthStep(string& auth_str);

			POP3_AUTH_STATE_E AuthEnd()
			{
				POP3_SET_AUTH_STATE(POP3_AUTH_END);
				sasl_gssapi.SaslDispose();
				return auth_state;
			}

			void AuthReset()
			{
				POP3_SET_AUTH_STATE(POP3_AUTH_INIT);
				POP3_RESET_STEP_COUNT();
				sasl_gssapi.SaslDispose();
				krb5_inst.Krb5Dispose();
			}

			virtual void AuthMechName(string& auth_name) const
			{
				auth_name = mech_name;
			}

			bool NeedsAuthCommand() const
			{
				return true;
			}
	};
}

#endif
