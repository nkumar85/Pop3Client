#include "pop3clearmech.h"

namespace pop3
{
	POP3_AUTH_STATE_E Pop3ClearMech::AuthStart(const Pop3AuthData_t& auth_data)
	{
		if(auth_state != POP3_AUTH_INIT)
		{
			POP3_DEBUG_AUTH("Invalid state to call AuthStart()\n");
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;
		}

		if(auth_data.user_name == "")
		{
			POP3_DEBUG_AUTH("Invalid user name specified for the mech = %s\n", mech_name.c_str());
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;
		}

		this->auth_data = auth_data;
		POP3_SET_AUTH_STATE(POP3_AUTH_CONTINUE);

	end:	
		return auth_state;
	}

	POP3_AUTH_STATE_E Pop3ClearMech::AuthStep(string& auth_str)
	{
		if(auth_state != POP3_AUTH_CONTINUE || !step_count)
		{
			POP3_DEBUG_AUTH("Invalid state to call AuthStep()\n");
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;
		}

		switch(step_count)
		{
			case 2:
			{
				auth_str = pop3command::USER + " " + auth_data.user_name;
				break;
			}

			case 1:
			{
				auth_str = pop3command::PASS + " " + auth_data.user_pass;
				POP3_SET_AUTH_STATE(POP3_AUTH_END);
				break;
			}

			default:
				break;
		}

		step_count--;

	end:
		return auth_state;
	}
}
