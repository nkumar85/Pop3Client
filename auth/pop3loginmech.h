#include "pop3authmodule.h"
#include "pop3authcommon.h"

#ifndef __POP3__LOGIN__AUTH__H
#define __POP3__LOGIN__AUTH__H

namespace pop3
{
	class Pop3LoginMech : public Pop3AuthModule
	{
		POP3_AUTH_STATE_E auth_state;
		const string mech_name;
		int step_count;
		Pop3AuthData_t auth_data;

		protected:
			UINT8 AuthStepCount() const 
			{
				return 2;
			}

		public:
			Pop3LoginMech() : auth_state(POP3_AUTH_INIT), mech_name("LOGIN")
			{
				step_count = AuthStepCount();
			}
			POP3_AUTH_STATE_E AuthStart(const Pop3AuthData_t& auth_data);
			POP3_AUTH_STATE_E AuthStep(string& auth_str);

			POP3_AUTH_STATE_E AuthEnd()
			{
				POP3_SET_AUTH_STATE(POP3_AUTH_END);
				return auth_state;
			}

			void AuthReset()
			{
				POP3_SET_AUTH_STATE(POP3_AUTH_INIT);
				POP3_RESET_STEP_COUNT();
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
