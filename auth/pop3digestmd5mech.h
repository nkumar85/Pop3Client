#include <common/pop3utils.h>
#include <common/pop3strtoken.h>
#include <debug/pop3debug.h>
#include "pop3authmodule.h"
#include "pop3authcommon.h"

#ifndef __POP3__DIGEST_MD5__H
#define __POP3__DIGEST_MD5__H

namespace pop3
{
	using namespace std;

	const string AUTH_INT = "00000000000000000000000000000000";
	
	typedef enum
	{
		QOP_INVALID,
		QOP_AUTH,
		QOP_AUTH_INT,
		QOP_AUTH_CONF
	}QOP_LIST_E;

	typedef enum
	{
		CIPHER_INVALID,
		CIPHER_3DES,
		CIPHER_DES,
		CIPHER_RC4_40,
		CIPHER_RC4,
		CIPHER_RC4_56
	}CIPHER_OPTS_E;

	typedef struct DigestMd5Challenge
	{
		string realm;
		string nonce;
		QOP_LIST_E qop_option;
		string stale;
		unsigned int maxbuf;
		string charset;
		string algorithm;
		CIPHER_OPTS_E cipher_value;
		string authzid;

		DigestMd5Challenge():realm(""), nonce(""), qop_option(QOP_INVALID), stale(""), maxbuf(0), 
								charset("utf-8"), algorithm("md5-sess"), cipher_value(CIPHER_INVALID), authzid("")
		{
		}
	}DigestMd5Challenge_t;

	typedef struct DigestMd5Params
	{
		string cnonce;
		string ncount;
		string user;
		string pass;
		string digest_uri;
	}DigestMd5Params_t;

	typedef enum
	{
		D_MD5_OK,
		D_MD_FAIL
	}D_MD5_STATUS_E;

	class Pop3DigestMd5Mech : public Pop3AuthModule
	{	
		private:
			DigestMd5Challenge_t d_md5_chal;
			DigestMd5Params_t d_md5_param;

			int ByteMd5(const char* data, const size_t data_len, char* output, const bool update = false, const bool finalize = true);
			void StringMd5(const char* data, string& output);
			int CalculateSecret(string& data, char* secret);
			int CalculateHA1(const char* secret, const size_t secret_len, const string& nonce, const string& cnonce, const string& authzid, string& result);
			int CalculateHA2(const string& auth_str, const string& digest_uri, const QOP_LIST_E qop, string& result);
			int CalculateRsp(const string& a1, const string& nonce, const string& nc, const string& cnonce, const string& qop, const string& a2, string& result);
			//int Base64Decode(const char* input, const size_t input_len, string& output);
			//int Base64Encode(const char* input, const size_t input_len, string& output);
			void AssignChallengeStruct(const string& token);

			void GenerateClientNonce(string& cnonce);
			D_MD5_STATUS_E ParseDigestChallenge(const string& challenge_str);
			D_MD5_STATUS_E ComputeDigestMd5Auth(const string& user, const string& pass, const string& digest_uri, string& response, bool client = true);
			bool VerifyServerResponseAuth(const string& response);

			POP3_AUTH_STATE_E auth_state;
			const string mech_name;
			int step_count;
			Pop3AuthData_t auth_data;
			MD5* md5;

		protected:
			UINT8 AuthStepCount() const 
			{
				return 2;
			}

		public:

			Pop3DigestMd5Mech() : auth_state(POP3_AUTH_INIT), mech_name("DIGEST-MD5"), md5(0)
			{
				step_count = AuthStepCount();
			}
			POP3_AUTH_STATE_E AuthStart(const Pop3AuthData_t& auth_data);
			POP3_AUTH_STATE_E AuthStep(string& auth_str);

			POP3_AUTH_STATE_E AuthEnd()
			{
				POP3_SET_AUTH_STATE(POP3_AUTH_END);
				POP3_RESET_STEP_COUNT();
				return auth_state;
			}

			void AuthReset()
			{
				POP3_SET_AUTH_STATE(POP3_AUTH_INIT);
			}

			virtual void AuthMechName(string& auth_name) const
			{
				auth_name = mech_name;
			}

			bool NeedsAuthCommand() const
			{
				return true;
			}

			~Pop3DigestMd5Mech()
			{
				if(md5)
				{
					delete md5;
					md5 = NULL;
				}
			}
	};
}

#endif
