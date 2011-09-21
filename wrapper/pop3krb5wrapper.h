/*
	Copyright 1990, 2008 by the Massachusetts Institute of Technology.

	This is basically scaled down version of kinit source code.

	C++ wrapper -- Copyright(c) 2011 heramba(heramba85@gmail.com)
*/

#ifndef __POP3_KRB5_WRAP__H
#define __POP3_KRB5_WRAP__H

#include <krb5.h>
#include <pwd.h>

#include <common/pop3commons.h>
#include <debug/pop3debug.h>

#define POP3_KRB5_DEBUG(code, fmt, ...)\
	Pop3KrbErrStr(code);\
	POP3_DEBUG_AUTH("%s "fmt, krb_msg.c_str(), ##__VA_ARGS__)

namespace pop3
{
	typedef enum { INIT_PW, INIT_KT, RENEW, VALIDATE } action_type;

	typedef enum POP3_KRB5_STATUS
	{
		POP3_KRB5_ERROR = -1,
		POP3_KRB5_OK
	}POP3_KRB5_STATUS_E;

	typedef struct Krb5CtxData
	{
		string principal;
		string ccache;
		string password;
		string hostname;
		string service;
	}Pop3Krb5CtxData_t;

	class Pop3Krb5Wrapper
	{
		friend krb5_error_code KRB5_CALLCONV kinit_prompter(krb5_context ctx, void *data, const char *name, 
					const char *banner, int num_prompts, krb5_prompt prompts[]);

		private:
			Pop3Krb5CtxData_t krb_data;
			krb5_context krb_ctx;
			krb5_ccache krb_ccache; 
			krb5_principal krb_princ; 
			char* name;
			string krb_msg;
			action_type action;
			bool api_init;

			inline void Pop3KrbErrStr(errcode_t err_code)
			{
				const char *krb_err_msg;
				krb_err_msg = krb5_get_error_message (krb_ctx, err_code);
				krb_msg = krb_err_msg;
				krb5_free_error_message (krb_ctx, krb_err_msg);
			}

		public:
			Pop3Krb5Wrapper()
			{
				action = INIT_PW;
				api_init = false;
			}
			POP3_KRB5_STATUS_E warn_unchecked_return Krb5Init(const Pop3Krb5CtxData_t& data);
			POP3_KRB5_STATUS_E warn_unchecked_return Krb5Begin();
			void Krb5Dispose();
			~Pop3Krb5Wrapper()
			{
				Krb5Dispose();
			}
	};
}
#endif
