#include <common/pop3defs.h>
#include <common/pop3strtoken.h>

#ifndef __POP3__CAPA__H
#define __POP3__CAPA__H

namespace pop3
{
	class Pop3Capabilities
	{
		private:
			map<string, string> cap_response_breakage;

		protected:
			bool is_command_supported(const string& command) const;

		public:
			Pop3Capabilities();
			//void parse_capability_reply(const char* cap_response);
			void parse_capability_reply(map<string,string>& cap_response);
			bool is_top_supported() const;
			bool is_sasl_supported(vector<string>& sasl_types) const;
			bool is_uidl_supported() const;
			bool is_clear_auth_supported() const;
			bool is_pipelining_supported() const;
			bool is_stls_supported() const;
			bool is_extended_codes_supported() const;
			int get_login_delay() const;
			int get_expire() const;
			void get_implementation(string& output) const;
	};
}
#endif
