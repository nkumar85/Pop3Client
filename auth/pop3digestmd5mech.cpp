#include "pop3digestmd5mech.h"

namespace pop3
{
	POP3_AUTH_STATE_E Pop3DigestMd5Mech::AuthStart(const Pop3AuthData_t& auth_data)
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

	POP3_AUTH_STATE_E Pop3DigestMd5Mech::AuthStep(string& auth_str)
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
				ParseDigestChallenge(auth_str);
				ComputeDigestMd5Auth(auth_data.user_name, auth_data.user_pass, "pop3/Dabba", auth_str);
				break;
			}

			case 1:
			{
				bool verify = VerifyServerResponseAuth(auth_str);
				auth_state = verify? POP3_AUTH_END: POP3_AUTH_ERROR;
				break;
			}

			default:
				break;
		}
		
		step_count--;

	end:
		return auth_state;
	}

	D_MD5_STATUS_E Pop3DigestMd5Mech::ParseDigestChallenge(const string& chall_str)
	{
		//Use string tokenizer
		//Trim \"\"
		//Dump into digest_md5_challenge
		string dec_str;
		Pop3AuthCommon::Base64Decode(chall_str, dec_str);

		StringTokenizer tokenizer(dec_str, ",", "");
		string data2;
		
		while(tokenizer.has_more_tokens())
		{
			tokenizer.next_token(data2);
			AssignChallengeStruct(data2);
			POP3_DEBUG_PRIV("Token data = %s\n", data2.c_str());
		}

		return D_MD5_OK;
	}

	/*
		Client verify:
		--------------
		1) byte_md5 = byte_md5(username:realm:password) //16 bytes

		2) A1 = byte_md5:server_nonce:client_nonce

		3) A2 = AUTHENTICATE:digest_uri

		4) response_1 = string_md5(A1)

		5) response_2 = server_nonce:nonce_count:client_nonce:qop:string_md5(A2)

		6) response_final = response_1:response_2

		7) digest_md5_response = string_md5(response_final)

		Server verify:
		--------------
		Same as Client verify except in step-3, 'AUTHENTICATE' string is ommitted (':' is retained)
	*/
	D_MD5_STATUS_E Pop3DigestMd5Mech::ComputeDigestMd5Auth(const string& user, const string& pass, const string& digest_uri, string& response, bool client)
	{
		//Compute as specified in RFC
		char output[16] = {0};
		string temp = user + ":" + d_md5_chal.realm + ":" + pass;
		CalculateSecret(temp, output);
		string nk;
		StringMd5(output, nk);

		string a1, a2;

		string cnonce, ncount;

		if(client)
		{
			d_md5_param.user = user;
			d_md5_param.pass = pass;
			GenerateClientNonce(cnonce);
			d_md5_param.cnonce = cnonce;
			d_md5_param.ncount = ncount = "00000001";
			d_md5_param.digest_uri = digest_uri;
		}

		CalculateHA1(output, 16, d_md5_chal.nonce, d_md5_param.cnonce, d_md5_chal.authzid, a1);

		if(client)
			CalculateHA2("AUTHENTICATE", digest_uri, d_md5_chal.qop_option, a2);
		else	
			CalculateHA2("", digest_uri, d_md5_chal.qop_option, a2);

		POP3_DEBUG_INFO2("A1: %s\n", a1.c_str());
		POP3_DEBUG_INFO2("A2: %s\n", a2.c_str());

		string rsp_hash = "";

		CalculateRsp(a1, d_md5_chal.nonce, d_md5_param.ncount, d_md5_param.cnonce, "auth", a2, rsp_hash);

		if(client)
		{
			string rsp = "charset=utf-8,username=\"" + user +"\",realm=\"" + d_md5_chal.realm + "\",nonce=\"" + d_md5_chal.nonce 
							+ "\",nc= " + ncount + ",cnonce=\"" + cnonce +
							"\",digest-uri=\"" + digest_uri +"\",response=" + rsp_hash + ",qop=auth";

			Pop3AuthCommon::Base64Encode(rsp, response);
			POP3_DEBUG_INFO2("Client D-MD5 Response: %s\n", rsp.c_str());
		}
		else
		{
			response = rsp_hash;	
		}

		POP3_DEBUG_INFO2("Final D-MD5 Response: %s\n", response.c_str());
		return D_MD5_OK;
	}

	bool Pop3DigestMd5Mech::VerifyServerResponseAuth(const string& response)
	{
		string dec_str = "", rsp = "";
		Pop3AuthCommon::Base64Decode(response, dec_str);

		string value1, value2;
		pop3_break_string2(dec_str, value1, value2, '=');	

		ComputeDigestMd5Auth(d_md5_param.user, d_md5_param.pass, d_md5_param.digest_uri, rsp, false);

		return (value2 == rsp);
	}

	int Pop3DigestMd5Mech::ByteMd5(const char* data, const size_t data_len, char* output, const bool update, const bool finalize)
	{
		if(md5 == 0)
		{
			md5 = MD5::GetInstance();
			if(md5 == 0)
			{
				return 0;
			}
		}

		UCHAR temp[16] = {0};

		if(update == false)
			md5->Md5Reset();
		
		md5->Md5Update(reinterpret_cast<UCHAR*>(const_cast<char*>(data)), static_cast<UINT>(data_len));

		if(finalize)
		{
			md5->Md5Final(temp);
			memcpy(output, temp, 16);
		}

		return 1;
	}

	int Pop3DigestMd5Mech::CalculateHA2(const string& auth_str, const string& digest_uri, const QOP_LIST_E qop, string& result)
	{
		char output[16] = {0};
		string temp = auth_str + ":" + digest_uri;
		if(qop > QOP_AUTH)
			temp += ":" + AUTH_INT;

		ByteMd5(temp.c_str(), temp.length(), output, false, true);
		StringMd5(output, result);

		return 1;
	}

	void Pop3DigestMd5Mech::StringMd5(const char* data, string& output)
	{
		MD5::Md5HexString(reinterpret_cast<UCHAR*>(const_cast<char*>(data)), output, true);
	}

	int Pop3DigestMd5Mech::CalculateSecret(string& data, char* secret)
	{
		return ByteMd5(data.c_str(), data.length(), secret, false, true);
	}

	int Pop3DigestMd5Mech::CalculateHA1(const char* secret, const size_t secret_len, const string& nonce,
									const string& cnonce, const string& authzid, string& result)
	{
		char output[16] = {0};
		ByteMd5(secret, secret_len, output, false, false);

		string temp = ":" + nonce + ":" + cnonce;
		if(authzid != "")
		{
			temp += ":" + authzid;
		}

		ByteMd5(temp.c_str(), temp.length(), output, true, true);
		StringMd5(output, result);

		return 1;
	}

	int Pop3DigestMd5Mech::CalculateRsp(const string& a1, const string& nonce, const string& nc, const string& cnonce, 
					const string& qop, const string& a2, string& result)
	{
		char output[16] = {0};
		string rsp = a1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + a2;
		ByteMd5(rsp.c_str(), rsp.length(), output, false, true);
		StringMd5(output, result);
		return 1;
	}

	void Pop3DigestMd5Mech::AssignChallengeStruct(const string& token)
	{
		string data1, data2;
		pop3_break_string2(token, data1, data2,'=');
		pop3_trim(data2, '\"', '\"', false);

		POP3_DEBUG_INFO2("Digest-MD5 pulled data = value -- %s = %s\n",data1.c_str(), data2.c_str());

		if(data1 == "realm")
		{
			d_md5_chal.realm = data2;
		}
		else if(data1 == "nonce")
		{
			d_md5_chal.nonce = data2;
		}
		else if(data1 == "qop")
		{
			if(data2 == "auth")
			{	
				d_md5_chal.qop_option = QOP_AUTH;
			}
			else if(data2 == "auth-int")
			{
				d_md5_chal.qop_option = QOP_AUTH_INT;
			}
			else if(data2 == "auth-conf")
			{
				d_md5_chal.qop_option = QOP_AUTH_CONF;
			}
			else
			{
				d_md5_chal.qop_option = QOP_INVALID;
			}
		}
		else if(data1 == "cipher")
		{
			if(data2 == "3des")
			{
				d_md5_chal.cipher_value = CIPHER_3DES;
			}
			else if(data2 == "des")
			{
				d_md5_chal.cipher_value = CIPHER_DES;
			}
			else if(data2 == "rc4-40")
			{
				d_md5_chal.cipher_value = CIPHER_RC4_40;
			}
			else if(data2 == "rc4")
			{
				d_md5_chal.cipher_value = CIPHER_RC4;
			}
			else if(data2 == "rc4-56")
			{
				d_md5_chal.cipher_value = CIPHER_RC4_56;
			}
			else
			{
				d_md5_chal.cipher_value = CIPHER_INVALID;
			}
		}
	}

	void Pop3DigestMd5Mech::GenerateClientNonce(string& cnonce)
	{
		uint64_t rand_num = 0;
		uint64_t rand_num2 = 0;

		pid_t pid = getpid();	
		pthread_t tid = pthread_self();

		srand(pid);
		rand_num += rand_r(reinterpret_cast<unsigned int*>(&pid));

		srand(tid);
		rand_num += rand_r(reinterpret_cast<unsigned int*>(&tid));

		struct timespec cur_time;
		clock_gettime(CLOCK_REALTIME, &cur_time);

		rand_num += cur_time.tv_sec;
		srand(cur_time.tv_sec);
		rand_num2 += rand_r(reinterpret_cast<unsigned int*>(&cur_time.tv_sec));
		rand_num2 += cur_time.tv_nsec;

		rand_num2 = rand_num2 << 32;
		rand_num |= rand_num2;

		stringstream ss;
		cnonce = ss.str();
		string temp = "";
		Pop3AuthCommon::Base64Encode(cnonce, temp);

		cnonce = temp;

		POP3_DEBUG_INFO1("D-MD5 client nonce = %s\n", cnonce.c_str());
	}
}
