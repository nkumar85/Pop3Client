#include "pop3capabilities.h"
#include "common/pop3defs.h"
#include "common/pop3utils.h"

namespace pop3
{
	void Pop3Capabilities::parse_capability_reply(map<string,string>& cap_response)
	{
		cap_response_breakage = cap_response;
	}

	bool Pop3Capabilities::is_command_supported(const string& command) const
	{
		return (cap_response_breakage.find(command) != cap_response_breakage.end());
	}	

	Pop3Capabilities::Pop3Capabilities()
	{
	}

	bool Pop3Capabilities::is_top_supported() const
	{
		return is_command_supported(pop3command::TOP);
	}

	bool Pop3Capabilities::is_sasl_supported(vector<string>& sasl_types) const
	{
		if(is_command_supported("SASL"))
		{
			string data = cap_response_breakage.find("SASL")->second;
			StringTokenizer token(data, " ", "\r\n");
			token.tokenize(sasl_types);
			pop3_remove_crlf(sasl_types[sasl_types.size()-1]);
			return true;
		}

		return false;
	}

	bool Pop3Capabilities::is_uidl_supported() const
	{
		return is_command_supported(pop3command::UIDL);
	}

	bool Pop3Capabilities::is_clear_auth_supported() const
	{
		return is_command_supported(pop3command::USER);
	}

	bool Pop3Capabilities::is_pipelining_supported() const
	{
		return is_command_supported("PIPELINING");
	}

	bool Pop3Capabilities::is_stls_supported() const
	{
		return is_command_supported(pop3command::STLS);
	}

	bool Pop3Capabilities::is_extended_codes_supported() const
	{
		return is_command_supported("RESP-CODES");
	}

	int Pop3Capabilities::get_login_delay() const
	{
		if(is_command_supported("LOGIN-DELAY"))
		{
			string temp = cap_response_breakage.find("LOGIN-DELAY")->second;
			pop3_remove_crlf(temp);
			int delay = 0;
			pop3_string_to_type(temp, delay);
			return delay;
		}

		return -1;
	}

	int Pop3Capabilities::get_expire() const
	{
		if(is_command_supported("EXPIRE"))
		{
			string temp = cap_response_breakage.find("EXPIRE")->second;
			pop3_remove_crlf(temp);
			int delay = 0;
			pop3_string_to_type(temp, delay);
			return delay;
		}

		return -1;
	}

	void Pop3Capabilities::get_implementation(string& output) const
	{
		if(is_command_supported("IMPLEMENTATION"))
		{
			output = cap_response_breakage.find("IMPLEMENTATION")->second;
			pop3_remove_crlf(output);
		}
	}
}
