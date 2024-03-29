#include "pop3gssapimech.h"

namespace pop3
{
	POP3_AUTH_STATE_E Pop3GssapiMech::AuthStart(const Pop3AuthData_t& auth_data)
	{
		Pop3Krb5CtxData_t krb5_data = {auth_data.user_name + "@" + auth_data.realm, "", auth_data.user_pass, auth_data.hostname, ""};
		Pop3SaslInfo_t gssapi_info = {auth_data.user_name, auth_data.user_pass, "","pop3", mech_name, auth_data.hostname};
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

		//Initialize the credential cache and get TGT
		if(krb5_inst.Krb5Init(krb5_data) != POP3_KRB5_OK)
		{
			POP3_DEBUG_AUTH("Kerberos init failed\n");
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;
		}

		if(krb5_inst.Krb5Begin() != POP3_KRB5_OK)
		{
			POP3_DEBUG_AUTH("Kerberos: retrieving TGT failed\n");
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;
		}

		//Now Initialize SASL library
		if(sasl_gssapi.SaslInit(gssapi_info) != POP3_SASL_OK)
		{
			POP3_DEBUG_AUTH("Sasl Init failed for mech = %s\n", mech_name.c_str());
			POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
			goto end;	
		}
		POP3_SET_AUTH_STATE(POP3_AUTH_CONTINUE);

	end:	
		return auth_state;
	}

	POP3_AUTH_STATE_E Pop3GssapiMech::AuthStep(string& auth_str)
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
			case 3:
			{
				if(sasl_gssapi.SaslStep(auth_info) != POP3_SASL_OK)
				{
					POP3_DEBUG_AUTH("SaslStep failed\n");
					POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
					goto end;
				}
				Pop3AuthCommon::Base64Encode(auth_info, auth_str);
				break;
			}

			case 2:
			case 1:
			{
				string auth_info;
				Pop3AuthCommon::Base64Decode(auth_str, auth_info);
				if(sasl_gssapi.SaslStep(auth_info) != POP3_SASL_OK)
				{					
					POP3_DEBUG_AUTH("SaslStep failed\n");
					POP3_SET_AUTH_STATE(POP3_AUTH_ERROR);
					goto end;
				}
				Pop3AuthCommon::Base64Encode(auth_info, auth_str);
				break;
			}

			default:
				break;
		}

		step_count--;
		if(!step_count)
		{
			POP3_SET_AUTH_STATE(POP3_AUTH_END);
		}

	end:
		return auth_state;
	}
}
