#include "pop3krb5wrapper.h"

/*
	Referred + Inherited from kinit and kdestroy source codes of MIT-krb5 API v1.9.1
*/

namespace pop3
{
	/*
		Here password has to be set.
		Instead of prompt, we directly fill the password provided by user.
		As of now only one prompt is handled since we do not support operations other than INIT_PW.
		We pass class context as data and make use of friend function kinit_prompter for getting password from class.
	*/

	krb5_error_code KRB5_CALLCONV kinit_prompter(krb5_context ctx, void *data, const char *name,
				const char *banner, int num_prompts, krb5_prompt prompts[])
	{
		Pop3Krb5Wrapper* krb_wrap = static_cast<Pop3Krb5Wrapper*>(data);
		memset(prompts[0].reply->data, 0, prompts[0].reply->length);
		strcpy(prompts[0].reply->data, krb_wrap->krb_data.password.c_str());
		prompts[0].reply->length = strlen(prompts[0].reply->data);
		POP3_DEBUG_INFO1("Password is : %s\n", prompts[0].reply->data);
		
		return 0;
	}

	POP3_KRB5_STATUS_E Pop3Krb5Wrapper::Krb5Init(const Pop3Krb5CtxData_t& data)
	{
		krb5_error_code code = 0;
		//int flags = 0;

		krb_data = data;
	
		POP3_DEBUG_INFO2("Krb5 data provided = principal=%s, ccache=%s, password=%s, hostname=%s, service=%s\n",
				krb_data.principal.c_str(), krb_data.ccache.c_str(), krb_data.password.c_str(), krb_data.hostname.c_str(), krb_data.service.c_str());

		code = krb5_init_context(&krb_ctx);
		if (code)
		{
			POP3_KRB5_DEBUG(code, "while initializing Kerberos 5 library");
			return POP3_KRB5_ERROR;
		}

		if (krb_data.ccache != "")
		{
			code = krb5_cc_resolve(krb_ctx, krb_data.ccache.c_str(), &krb_ccache);
			if (code != 0)
			{
				POP3_KRB5_DEBUG(code, "%s : resolving ccache %s", krb_msg.c_str(), krb_data.ccache.c_str());
				return POP3_KRB5_ERROR;
			}

			POP3_DEBUG_INFO1("Using specified cache: %s\n", krb_data.ccache.c_str());
		}
		else
		{
			if ((code = krb5_cc_default(krb_ctx, &krb_ccache)))
			{
				POP3_KRB5_DEBUG(code, "while getting default ccache");
				return POP3_KRB5_ERROR;
			}
			POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Using default cache: %s\n", krb5_cc_get_name(krb_ctx, krb_ccache));
    		}

		if(krb_data.principal != "")
		{
			/* Use specified name */
			//if((code = krb5_parse_name_flags(krb_ctx, krb_data.principal.c_str(), flags, &krb_princ)))
			if((code = krb5_parse_name(krb_ctx, krb_data.principal.c_str(), &krb_princ)))
			{
				POP3_KRB5_DEBUG(code, "when parsing name %s", krb_data.principal.c_str());
				return POP3_KRB5_ERROR;
			}
		}

		code = krb5_unparse_name(krb_ctx, krb_princ, &name);
		if(code)
		{
			POP3_KRB5_DEBUG(code, "when unparsing name");
			return POP3_KRB5_ERROR;
		}

		POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Using principal: %s\n", name);
		api_init = true;

		return POP3_KRB5_OK;
	}

	POP3_KRB5_STATUS_E Pop3Krb5Wrapper::Krb5Begin()
	{
		int notix = 1;
		krb5_keytab keytab = 0;
		krb5_creds my_creds;
		krb5_error_code code = 0;
		krb5_get_init_creds_opt *options = NULL;

		memset(&my_creds, 0, sizeof(my_creds));

//		code = krb5_get_init_creds_opt_alloc(krb_ctx, &options);
//		if(code)
//			goto cleanup;

	/*
		From this point on, we can goto cleanup because my_creds is
		initialized.
	*/

//No need for these things?

/*
	if(opts->lifetime)
		krb5_get_init_creds_opt_set_tkt_life(options, opts->lifetime);
	if(opts->rlife)
		krb5_get_init_creds_opt_set_renew_life(options, opts->rlife);
	if(opts->forwardable)
		krb5_get_init_creds_opt_set_forwardable(options, 1);
	if(opts->not_forwardable)
		krb5_get_init_creds_opt_set_forwardable(options, 0);
	if(opts->proxiable)
		krb5_get_init_creds_opt_set_proxiable(options, 1);
	if(opts->not_proxiable)
		krb5_get_init_creds_opt_set_proxiable(options, 0);
	if(opts->canonicalize)
		krb5_get_init_creds_opt_set_canonicalize(options, 1);
	if(opts->anonymous)
		krb5_get_init_creds_opt_set_anonymous(options, 1);
	if(opts->addresses)
	{
		krb5_address **addresses = NULL;
		code = krb5_os_localaddr(k5->ctx, &addresses);
		if(code != 0)
		{
			POP3_KRB5_DEBUG(code, "getting local addresses");
			goto cleanup;
		}
		krb5_get_init_creds_opt_set_address_list(options, addresses);
	}

	if(opts->no_addresses)
		krb5_get_init_creds_opt_set_address_list(options, NULL);
	if(opts->armor_ccache)
		krb5_get_init_creds_opt_set_fast_ccache_name(k5->ctx, options, opts->armor_ccache);

	if((opts->action == INIT_KT) && opts->keytab_name)
	{
		code = krb5_kt_resolve(k5->ctx, opts->keytab_name, &keytab);
		if(code != 0)
		{
			POP3_KRB5_DEBUG(code, "resolving keytab %s", opts->keytab_name);
			goto cleanup;
		}

		if(opts->verbose)
			POP3_DEBUG(pop3debug::POP3_DEBUG_AUTH, "Using keytab: %s\n", opts->keytab_name);
	}

	int i = 0;
	for(i = 0; i < opts->num_pa_opts; i++)
	{
		code = krb5_get_init_creds_opt_set_pa(krb_ctx, options, opts->pa_opts[i].attr, opts->pa_opts[i].value);
		if(code != 0)
		{
			POP3_KRB5_DEBUG(code, "while setting '%s'='%s'", opts->pa_opts[i].attr, opts->pa_opts[i].value);
			goto cleanup;
		}

		if(opts->verbose)
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_AUTH, "PA Option %s = %s\n", opts->pa_opts[i].attr, opts->pa_opts[i].value);
		}
	}*/

	/*code = krb5_get_init_creds_opt_set_out_ccache(krb_ctx, options, krb_ccache);
	if(code)
	{
		goto cleanup;
	}*/

	/* We may not require actions other than INIT_PW */
	switch(action)
	{
		case INIT_PW:
			code = krb5_get_init_creds_password(
						krb_ctx, /* Kerberos context*/
						&my_creds, /* The credentials */
						krb_princ, /* The principal */
						const_cast<char*>(krb_data.password.c_str()), /* The password */
						NULL,
						this, /* Context */
						0, /* Start Time */
						NULL, /* Service Name */
						options /* Credential options */
						);
		break;

		default:
			goto cleanup;
#if 0
		case INIT_KT:
			code = krb5_get_init_creds_keytab(
					krb_ctx,
					&my_creds,
					krb_princ,
					keytab,
					0,
					(char*)krb_data.service.c_str(),
					options
					);
		break;

		case VALIDATE:
			code = krb5_get_validated_creds(
					krb_ctx,
					&my_creds,
					krb_princ,
					krb_ccache,
					(char*)krb_data.service.c_str()
					);
		break;

		case RENEW:
			code = krb5_get_renewed_creds(
					krb_ctx,
					&my_creds,
					krb_princ,
					krb_ccache,
					(char*)krb_data.service.c_str()
					);
			break;
#endif
	}

	if(code)
	{
		string doing;

		switch(action)
		{
			case INIT_PW:
			case INIT_KT:
				doing = "getting initial credentials";
				break;

			case VALIDATE:
				doing = "validating credentials";
				break;

			case RENEW:
				doing = "renewing credentials";
				break;
		}

		if(code == KRB5KRB_AP_ERR_BAD_INTEGRITY)
		{
            POP3_DEBUG(pop3debug::POP3_DEBUG_AUTH, "Password incorrect while %s\n", doing.c_str());
		}
		else
		{
			POP3_KRB5_DEBUG(code, "while %s\n", doing.c_str());
		}

		goto cleanup;
	}

	/* Yippeeeeeeeee we got the ticket. Store it!*/
	POP3_DEBUG_INFO1("Ticket initialization succeeded\n");

	/* This is the guy who stores ticket file */
	code = krb5_cc_initialize(krb_ctx, krb_ccache, krb_princ);

	if(code)
	{
		POP3_KRB5_DEBUG(code, " while initializing credential cache\n");
		goto cleanup;
	}

	code = krb5_cc_store_cred(krb_ctx, krb_ccache, &my_creds);

	if(code)
	{
		POP3_KRB5_DEBUG(code, " while storing ticket data\n");
		goto cleanup;
	}

	/* We may not requiire this */
/*
	if((action != INIT_PW) && (action != INIT_KT))
	{
		code = krb5_cc_initialize(krb_ctx, krb_ccache, krb_princ);
		if(code)
		{
			POP3_KRB5_DEBUG(code, "when initializing cache %s\n",krb5_cc_get_name(krb_ctx, krb_ccache));
			goto cleanup;
		}
		POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Initialized cache\n");

		code = krb5_cc_store_cred(krb_ctx, krb_ccache, &my_creds);
		if(code)
		{
			POP3_KRB5_DEBUG(code, "while storing credentials\n");
			goto cleanup;
		}
		POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, "Stored credentials\n");
	}
*/

	notix = 0;

cleanup:

		if(options)
		{
			krb5_get_init_creds_opt_free(krb_ctx, options);
		}

		if(my_creds.client == krb_princ)
		{
			my_creds.client = 0;
		}

		/*
		if(opts->pa_opts)
		{
			free(opts->pa_opts);
			opts->pa_opts = NULL;
			opts->num_pa_opts = 0;
		}
		*/

		krb5_free_cred_contents(krb_ctx, &my_creds);
		if(keytab)
		{
			krb5_kt_close(krb_ctx, keytab);
		}
		
		return notix?POP3_KRB5_ERROR:POP3_KRB5_OK;
	}

	void Pop3Krb5Wrapper::Krb5Dispose()
	{
		if(name)
		{
			krb5_free_unparsed_name(krb_ctx, name);
		}

		if(krb_princ)
		{
			krb5_free_principal(krb_ctx, krb_princ);
		}

		if(krb_ccache)
		{
			krb5_cc_close(krb_ctx, krb_ccache);
			krb5_cc_destroy(krb_ctx, krb_ccache);
		}

		if(krb_ctx)
		{
			krb5_free_context(krb_ctx);
		}
	}
}
