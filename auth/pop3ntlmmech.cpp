#include "pop3ntlmmech.h"

namespace pop3
{
	POP3_AUTH_STATE_E Pop3NtlmMech::AuthStart(const Pop3AuthData_t& auth_data)
	{
		Pop3SaslInfo_t ntlm_info = {auth_data.user_name, auth_data.user_pass, "","", mech_name, auth_data.hostname};
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
		if(sasl_ntlm.SaslInit(ntlm_info) != POP3_SASL_OK)
		{
			POP3_DEBUG_AUTH("Sasl Init failed for mech = %s\n", mech_name.c_str());
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;	
		}
		POP3_SET_AUTH_STATE(POP3_AUTH_CONTINUE);

	end:	
		return auth_state;
	}

	POP3_AUTH_STATE_E Pop3NtlmMech::AuthStep(string& auth_str)
	{
		string auth_info;
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
				if(sasl_ntlm.SaslStep(auth_info) != POP3_SASL_OK)
				{
					POP3_DEBUG_AUTH("SaslStep failed\n");
					POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
					goto end;
				}
				Pop3AuthCommon::Base64Encode(auth_info, auth_str);
				break;
			}

			case 1:
			{
				string auth_info;
				Pop3AuthCommon::Base64Decode(auth_str, auth_info);
				if(sasl_ntlm.SaslStep(auth_info) != POP3_SASL_OK)
				{					
					POP3_DEBUG_AUTH("SaslStep failed\n");
					POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
					goto end;
				}
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
