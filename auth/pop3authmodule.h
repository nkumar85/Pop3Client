#include <common/pop3commons.h>
#include <debug/pop3debug.h>
#include <common/pop3defs.h>

#ifndef __POP3__AUTH__MODULE__H
#define __POP3__AUTH__MODULE__H

namespace pop3
{
	#define	POP3_SET_AUTH_STATE(x) this->auth_state = x
	#define POP3_RESET_STEP_COUNT() this->step_count = AuthStepCount()

	typedef enum POP3_AUTH_STATE
	{
		POP3_AUTH_ERROR = -1,
		POP3_AUTH_INIT,
		POP3_AUTH_CONTINUE,
		POP3_AUTH_END
	}POP3_AUTH_STATE_E;

	typedef struct Pop3AuthData
	{
		string user_name;
		string auth_name;
		string user_pass;
		string hostname;
		string service;
		string realm;
	}Pop3AuthData_t;

	typedef struct Pop3AuthMechConfig
	{
		bool sasl;
		UINT8 step_count;
		string mech_name;
	}Pop3AuthMechConfig_t;

	static Pop3AuthMechConfig_t POP3_AUTH_MECH_REPO[] = 
	{
		{false, 2, "CLEAR"},
		{true,  1, "ANONYMOUS"},
		{false, 1, "APOP"},
		{true,  1, "PLAIN"},
		{true,  2, "LOGIN"},
		{true,  1, "CRAM-MD5"},
		{true,  2, "DIGEST-MD5"},
		{true,  2, "NTLM"},
		{true,  3, "GSSAPI"}
	};

	class Pop3AuthModule
	{
		protected:
			virtual UINT8 AuthStepCount() const = 0;

		public:
			virtual POP3_AUTH_STATE_E AuthStart(const Pop3AuthData_t& auth_data) = 0;
			virtual POP3_AUTH_STATE_E AuthStep(string& auth_str)  = 0;
			virtual POP3_AUTH_STATE_E AuthEnd() = 0;
			virtual void AuthReset() = 0;
			virtual void AuthMechName(string& auth_name) const = 0;
			virtual bool NeedsAuthCommand() const = 0;
			virtual ~Pop3AuthModule() = 0;
	};
}

#endif
