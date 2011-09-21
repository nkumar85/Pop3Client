#include "pop3saslwrapper.h"

namespace pop3
{

	int getauthname_func(void *context, int id, const char **result, unsigned *len)
	{
		if(context)
		{
			Pop3SaslWrapper* sasl_mgr = static_cast<Pop3SaslWrapper*>(context);
			switch (id) 
			{
				case SASL_CB_USER:
				{
					if (result != NULL)
					{
						*result = sasl_mgr->sasl_data.user_name.c_str();
					}

					if ((len != NULL) && (result != NULL))
					{
						*len = strlen(*result);
					}
				}
				break;

				case  SASL_CB_AUTHNAME:
				{
					if (result != NULL)
					{
						*result = sasl_mgr->sasl_data.user_name.c_str();
					}
					if ((len != NULL) && (result != NULL))
					{
						*len = strlen(*result);
					}
				}
				break;

				default:
					break;
			}

			return SASL_OK;
		}

		return SASL_FAIL;
	}

	int getsecret_func(sasl_conn_t *conn, void *context, int id, sasl_secret_t **psecret)
	{
		Pop3SaslWrapper* sasl_mgr = static_cast<Pop3SaslWrapper*>(context);
			
		if(id == SASL_CB_PASS)
		{
			*psecret =  sasl_mgr->secret;
			return SASL_OK;
		}

		return SASL_FAIL;
	}

	/*int getrealm_func(void *context, int id, const char **availrealms, const char **result)
	{
		return SASL_OK;
	}*/

	int getcannonical_user_func(sasl_conn_t *conn, void *context, const char *in, unsigned inlen,  unsigned flags,
				const char *user_realm, char *out, unsigned out_max, unsigned *out_len)
{

		if((NULL !=out) && (NULL != in))
		{
				strncpy( out,in,strlen(in));
				out_max = 8192;
				*out_len=strlen(in);
				return(SASL_OK); 
		}
				return(SASL_BADPROT); 
}

	POP3_SASL_STATE_E Pop3SaslWrapper::SaslInit(const Pop3SaslInfo_t& sasl_data)
	{
		if(sasl_data.user_name == "")
		{
			return POP3_SASL_ERROR;
		}
		
		this->sasl_data = sasl_data;

		//Initialize the callbacks
		/*sasl_callback[0].id  = SASL_CB_GETREALM;
		sasl_callback[0].proc = (int (*)())getrealm_func;
		sasl_callback[0].context = this;*/

		sasl_callback[0].id  = SASL_CB_USER;
		sasl_callback[0].proc = (int (*)())getauthname_func;
		sasl_callback[0].context = this;
		
		sasl_callback[1].id  = SASL_CB_AUTHNAME;
		sasl_callback[1].proc = (int (*)())getauthname_func;
		sasl_callback[1].context = this;

		sasl_callback[2].id  = SASL_CB_PASS;
		sasl_callback[2].proc = (int (*)())getsecret_func;
		sasl_callback[2].context = this;

		sasl_callback[3].id =  SASL_CB_CANON_USER;
		sasl_callback[3].proc = (int (*)())getcannonical_user_func;
		sasl_callback[3].context = this;

		sasl_callback[4].id  = SASL_CB_LIST_END;
		sasl_callback[4].proc = 0;
		sasl_callback[4].context = this;
	
		//Initialize the secret
		//If the allocated memory does not include length of password, the program results in memory corruption
		secret = (sasl_secret_t*) malloc(sizeof(sasl_secret_t)+sasl_data.user_pass.length());
		if(secret == 0)
		{
			//Error
			POP3_SASL_DEBUG("SASL-Error: Memory allocation failed\n");
			return POP3_SASL_ERROR;
		}

		secret->len = sasl_data.user_pass.length();
		memcpy(secret->data, sasl_data.user_pass.c_str(), secret->len);

		int sasl_result = sasl_client_init(0);

		if(sasl_result != SASL_OK)
		{
			//Error
			POP3_SASL_DEBUG("SASL-Error 2\n");
			return POP3_SASL_ERROR;
		}

		sasl_result = sasl_client_new(sasl_data.service.c_str(), sasl_data.hostname.c_str(), NULL, NULL, sasl_callback, 0, &conn);
		if(sasl_result != SASL_OK)
		{
			//Error
			POP3_SASL_DEBUG("SASL-Error 3\n");
			return POP3_SASL_ERROR;
		}

		memset(&secprops, 0, sizeof(secprops));
		secprops.maxbufsize = 8192; //TODO: Needs change
		secprops.max_ssf = UINT_MAX;
		sasl_result = sasl_setprop(conn, SASL_SEC_PROPS, &secprops);

		if(sasl_result != SASL_OK)
		{
			POP3_SASL_DEBUG("sasl_setprop failed\n");
			return POP3_SASL_ERROR;
		}

		return POP3_SASL_OK;
	}

	POP3_SASL_STATE_E Pop3SaslWrapper::SaslStep(string& auth_str)
	{
		int sasl_result;
		const char* out = NULL;
		unsigned int outlen = 0;
		if(init == false)
		{				
			string mechlist = sasl_data.mech;
			const char *mechusing;

			do
			{
				sasl_result = sasl_client_start(conn, mechlist.c_str(), &client_interact, &out, &outlen, &mechusing);
			}while(sasl_result == SASL_INTERACT);
				
			if(sasl_result != SASL_CONTINUE)
			{
				//Log Error
				POP3_SASL_DEBUG("SASL-Error 4 - \n");
				return POP3_SASL_ERROR;
			}

			init = true;
			auth_str.assign(out, outlen);				
			return POP3_SASL_OK;
		}

		do
		{
			sasl_result = sasl_client_step(conn, auth_str.c_str(), auth_str.length(), &client_interact, &out, &outlen);
			POP3_DEBUG_INFO1("sasl_result : %d\n", sasl_result);

		}while(sasl_result == SASL_INTERACT);

		if(sasl_result != SASL_OK && sasl_result != SASL_CONTINUE)
		{
			//Log Error
			POP3_SASL_DEBUG("SASL-Error 5 -- \n");
			return POP3_SASL_ERROR;
		}
		
		auth_str.assign(out, outlen);
		return POP3_SASL_OK;

	}
	
	void Pop3SaslWrapper::SaslDispose()
	{
		if(secret)
		{
			free(secret);
			secret = NULL;
		}

		sasl_dispose(&conn);
		sasl_done();
	}

	Pop3SaslWrapper::~Pop3SaslWrapper()
	{
		SaslDispose();
	}
}
