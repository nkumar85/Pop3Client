#include "pop3crammd5mech.h"

namespace pop3
{
	POP3_AUTH_STATE_E Pop3CramMd5Mech::AuthStart(const Pop3AuthData_t& auth_data)
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

	POP3_AUTH_STATE_E Pop3CramMd5Mech::AuthStep(string& auth_str)
	{
		string auth_info = "";

		if(auth_state != POP3_AUTH_CONTINUE || !step_count)
		{
			POP3_DEBUG_AUTH("Invalid state to call AuthStep()\n");
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;
		}

		Pop3AuthCommon::Base64Decode(auth_str, auth_info);

		switch(step_count)
		{
			case 1:
			{
				Pop3AuthCommon::HmacMd5String(auth_info, auth_data.user_pass, auth_str, true);
				auth_info = auth_data.user_name + " " + auth_str;
				Pop3AuthCommon::Base64Encode(auth_info, auth_str);
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
