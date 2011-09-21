/*#include "pop3client.h"
#include "pop3debug.h"
#include "pop3utils.h"
#include "pop3strtoken.h"
#include "pop3digestmd5.h"*/
#include "pop3client.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <string.h>
#include <time.h>
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>

#include<iostream>
#include<vector>
#include<sstream>

using namespace pop3;

void pop3_print_usage();
void pop3_start_prompt();
void pop3_exit_prompt();
bool pop3_get_statistics(unsigned int& j, unsigned int& k);
bool pop3_set_param(const char*, const char*);
void pop3_print_usage(void);
void pop3_print_examples(void);
void pop3_print_interactive_usage();
bool pop3_str2int(const string&, int&);
bool pop3_int2str(const long long&, string&);
void pop3_str_split(const string& source, vector<string>& dest);
void pop3_fail(const char*);
bool pop3_retr_mail(unsigned int mail_index, const string& op);
bool pop3_delete_mail(unsigned int mail_index);

#define POP3_CHECK_PARAM(key, val)\
	if(val == 0){printf("The mandatory param = %s has invalid value\n", key); return false;}

Pop3Params params = {"", 110, pop3ssl::POP3_SSL_DISABLE, pop3verifytype::POP3_SSL_ACCEPT_IMPORTED_CERT, pop3auth::POP3, 30, "", "", "/etc/ssl/certs", ""};
Pop3Client* pop3_client = 0;
bool interactive = false;

void pop3_print_usage(void)
{
	printf("\n[***************************** USAGE ********************************]\n\n");
	printf("Pop3Client [-s(--server) server][-p(--port) port][--user user][--pass pass][--auth auth-method]\n");
	printf("           [-t(--timeout) timeout][--ssl ssl][--sslmode ssl-mode][--ca cacert-path] [-i]\n\n");
	printf("\n");
	printf("\tserver = Mandatory FQDN/IPv4/IPv6 address of the server\n\n");
	printf("\tport = Optional port number of the pop3 server [default = 110]\n\n");
	printf("\tuser = Mandatory user name to authenticate\n\n");
	printf("\tpass = Mandatory password to authenticate (Optional for CLEAR-TEXT auth)\n\n");
	printf("\tauth-method = Optional Authentication method [should be an integer between 0-8]\n");
	printf("\t\t0 = CLEAR-TEXT [USER/PASS] (default), 1 = ANONYMOUS, 2 = APOP, 3 = PLAIN, 4 = LOGIN, ");
	printf("5 = CRAM-MD5, 6 = DIGEST-MD5, 7 = NTLM, 8 = KERBEROS\n\n");
	printf("\ttimeout = Optional timeout parameter(connect + socket) [default = 30 seconds]\n\n");
	printf("\tssl = Optional SSL settings [should be an integer between 0-2]\n");
	printf("\t\t0 = SSL Disable, 1 = STARTTLS, 2 = Normal SSL\n\n");
	printf("\tssl-mode = Optional SSL mode [should be an integer between 0-1]\n");
	printf("\t\t0 = Accept All Certificates, 1 = Verify with CA certificate\n\n");
	printf("\tcacert-path = Optional ca-certificate path for CA verification when ssl-mode=1 [default=/etc/ssl/certs]\n\n");
	printf("\t-i = This option enables interactive mode once successfully authenticated to server.");
	printf(" Type 'help' in interactive mode for usage\n\n");

	pop3_print_examples();
}

void pop3_print_examples(void)
{
	printf("\tEXAMPLES:\n");
	printf("\t---------\n");
	printf("\t1) SIMPLE EXAMPLE: Just authenticate to POP3 Server with CLEAR TEXT AUTH\n");
	printf("\t\t./Pop3Client -s 192.168.100.10 --user myuser --pass mypass\n");
}

void pop3_print_interactive_usage()
{
	printf("\tstat = Get staticstics from pop3 server\n");
	printf("\tretr <index> = retrieve mail from server\n");
	printf("\t\tindex = n'th mail in server; 0 = retrieve all mails (default)\n");
	printf("\tdel <index> - delete mail from server\n");
	printf("\tquit = quit the prompt\n");
}

bool pop3_str2int(const string& str, int& value)
{
	stringstream ss;
	ss<<str;
	ss>>value;
	return ss.eof();
}

bool pop3_int2str(const long long& k, string& d)
{
	stringstream ss;
	ss<<k;
	ss>>d;
	return ss.eof();
}

void pop3_str_split(const string& source, vector<string>& dest)
{
	stringstream ss;
	ss<<source;
	while(!ss.eof())
	{
		string value;
		ss>>value;
		dest.push_back(value);
	}
}

void pop3_fail(const char* msg)
{
	printf(msg);
	exit(EXIT_FAILURE);
}

void pop3_start_prompt()
{
	printf("Starting interactive mode. Type 'help' for usage\n");
	while(true)
	{
		char buf[256] = {0};
		printf("prompt>");
		cin.getline(buf, 255);

		vector<string> args;
		pop3_str_split(buf, args);

		if(strcasecmp(args[0].c_str(), "help") == 0)
		{
			pop3_print_interactive_usage();
			continue;
		}

		if(strcasecmp(args[0].c_str(), "stat") == 0)
		{
			unsigned int j = 0, k = 0;
			if(pop3_get_statistics(j, k) == false)
			{
				printf("There was an error getting mail server statistics\n");
				break;
			}
			printf("There are %u mails in server measuring %u bytes\n", j, k);
			continue;
		}

		if(strcasestr(args[0].c_str(), "retr") != 0 || strcasestr(args[0].c_str(), "del") != 0)
		{
			int index = 0;
			if(!pop3_str2int(args[1], index) || index < 0)
			{
				printf("Invalid message id specified\n");
				continue;
			}

			if(pop3_retr_mail(index, args[0]) == false)
			{
				printf("There was error during %s operation\n", args[0].c_str());
				break;
			}
			continue;
		}

		if(strcasecmp(args[0].c_str(),"quit") == 0)
		{
			pop3_exit_prompt();
			break;
		}

		printf("--Invalid command. Type 'help' for usage\n");
	}
}

void pop3_exit_prompt()
{
}

bool pop3_set_param(const char* key, const char* value)
{
	int temp = 0;
	if(strcasecmp(key, "s") == 0 || strcasecmp(key, "server") == 0)
	{
		//Set server param
		POP3_CHECK_PARAM(key, value);
		params.host = value;
		return true;
	}

	
	if((strcasecmp(key, "p") == 0 || strcasecmp(key, "port") == 0) && value)
	{
		//Set server param
		if(pop3_str2int(value, temp) && temp > 0)
			params.portNo = temp;
		else
			printf("Invalid port number specified. Defaulting...\n");
		return true;
	}

	if(strcasecmp(key, "user") == 0)
	{
		POP3_CHECK_PARAM(key, value);
		params.pop3User = value;
		return true;
	}

	if(strcasecmp(key, "pass") == 0 && value)
	{
		params.pop3Pass = value;
		return true;
	}

	if(strcasecmp(key, "ssl") == 0 && value)
	{
		if(!pop3_str2int(value, temp) || (temp < 0) || (temp > 2))
		{
			printf("%s value is out of bounds OR invalid value specified\n", key);
			return false;
		}
		params.sslEnable = static_cast<pop3ssl::Pop3Ssl>(temp);
		return true;
	}
	
	if(strcasecmp(key, "auth") == 0 && value)
	{
		if(!pop3_str2int(value, temp) || (temp < 0) || (temp > 8))
		{
			printf("%s value is out of bounds OR invalid value specified\n", key);
			return false;
		}
		params.pop3Auth = static_cast<pop3auth::POP3_AUTH_TYPE_E>(temp);
		return true;
	}

	if(strcasecmp(key, "sslmode") == 0 && value)
	{
		if(!pop3_str2int(value, temp) || (temp & 0xFE))
		{
			printf("%s value is out of bounds OR invalid value specified\n", key);
			return false;
		}
		params.sslVerifyType = static_cast<pop3verifytype::Pop3VerifyType>(temp);                
		return true;
	}

	if((strcasecmp(key, "t") == 0 || strcasecmp(key, "timeout") == 0) && value)
	{
		if(!pop3_str2int(value, temp) || temp <= 0)
		{
			printf("%s has invalid value\n", key);
			return false;
		}
		params.timeout = temp;
		return true;
	}

	if(strcasecmp(key, "ca") == 0 && value)
	{
		params.ca_path = value;
		return true;
	}

	printf("Invalid option = %s. Ignoring.....\n", key);
	return true;
}

void pop3_check_params(Pop3Params& params)
{
	if(params.host == "")
	{
		printf("Server value is unspecified\n");
		goto error;
	}

	if(params.pop3User == "")
	{
		printf("User value is unspecified\n");
		goto error;
	}

	if(params.pop3Auth > pop3auth::POP3 && params.pop3Pass == "")
	{
		printf("Current auth settings cannot have blank password\n");
		goto error;
	}

	if(params.sslEnable > pop3ssl::POP3_SSL_DISABLE)
	{
		if(params.sslVerifyType == pop3verifytype::POP3_SSL_VERIFY_IMPORTED_CERT && params.ca_path == "")
		{
			printf("No CA path specified defaulting..\n");
		}
	}

	return;

error:
	pop3_print_usage();
	exit(EXIT_FAILURE);
}

void pop3_parse_args(int argc, char **argv)
{
	int c, option_index = 0;

	static struct option long_options[] =
	{
		{"server",  1, 0,  0 },
		{"port",    1, 0,  0 },
		{"user",    1, 0,  0 },
		{"pass",    1, 0,  0 },
		{"auth",    1, 0,  0 },
		{"timeout", 1, 0,  0 },
		{"ssl",     1, 0,  0 },
		{"sslmode", 1, 0,  0 },
		{"ca",      1, 0,  0 },
		{"help",    0, 0,  0 },
		{0,         0, 0,  0 }
	};

	while(1)
	{
		c = getopt_long(argc, argv, "s:p:t:hi", long_options, &option_index);

		if (c == -1)
			break;

		switch(c)
		{
			case 0:
				if(pop3_set_param(long_options[option_index].name, optarg) == false)	
				{
					pop3_print_usage();
					exit(EXIT_FAILURE);
				}
				break;

			case 's':
				if(pop3_set_param("s", optarg) == false)
				{
					pop3_print_usage();
					exit(EXIT_FAILURE);
				}
				break;

			case 'p':
				if(pop3_set_param("p", optarg) == false)
				{
					pop3_print_usage();
					exit(EXIT_FAILURE);
				}
				break;

			case 't':
				if(pop3_set_param("t", optarg) == false)
				{
					pop3_print_usage();
					exit(EXIT_FAILURE);
				}
				break;

			case 'i':
				interactive = true;
				break;

			case 'h':
				pop3_print_usage();
				exit(EXIT_SUCCESS);
				break;

			default:
				printf("Invalid option specified\n");
		}
	}

	if (optind < argc)
	{
		printf("non-option ARGV-elements: ");
		while (optind < argc)
		{
			printf("%s ", argv[optind++]);
		}
		printf("\n");
	}
}

bool pop3_get_statistics(unsigned int& j, unsigned int& k)
{
	if(pop3_client->Pop3Stat(j,k) != pop3status::POP3_STATUS_OK)
	{
		return false;
	}
	return true;
}

bool pop3_retr_mail(unsigned int mail_index, const string& op)
{
 	unsigned int j = 0, k = 0;
	if(pop3_get_statistics(j, k) == false)
	{
		return false;
	}

	if(!j)
	{
		printf("There are no mails in the server\n");
		return true;
	}

	char cwd[256] = {0};
	string path = getcwd(cwd, 255);

	unsigned int iteration = 1;

	if(mail_index == 0)
	{
		iteration = j;
		mail_index = 1;
	}

	while(iteration > 0)
	{
		if(op == "retr")
		{
			string name;
			pop3_int2str(time(NULL), name);
			string retr_path = path + "/mail_" + name;
			pop3_int2str((int) mail_index, name);
			retr_path += "_"+name;

			if(pop3_client->Pop3Retrieve(mail_index, retr_path, false) != pop3status::POP3_STATUS_OK)
			{
				printf("Unable to retrieve mail with msg-id = %d\n", mail_index);
				return false;
			}
			printf("Successfully downloaded mail with msg-id = %d\n", mail_index);
		}
		else if(op=="del")
		{
			if(pop3_client->Pop3Delete(mail_index) != pop3status::POP3_STATUS_OK)
			{
				printf("Unable to delete mail with msg-id = %d\n", mail_index);
				return false;
			}
		}
		else	
		{
			printf("Invalid operation specified\n");
			return false;
		}

		mail_index++;
		iteration--;
	}
	return true;
}

int main(int argc, char** argv)
{
	pop3_parse_args(argc, argv);
	pop3_check_params(params);
	pop3_client  = new Pop3Client(params);
	if(pop3_client->Pop3Init() != pop3status::POP3_STATUS_OK)
	{
	    delete pop3_client;
		pop3_fail("POP3 Client Init() failed\n");
	}
	
	if(pop3_client->Pop3Connect() != pop3status::POP3_STATUS_OK)
	{
	    delete pop3_client;
		pop3_fail("Pop3 Client Connect() failed\n");
	}
//	pop3_client->Pop3StartTls();
    
	if(pop3_client->Pop3Authenticate() != pop3status::POP3_STATUS_OK)
    {
	    pop3_client->Pop3Quit();
        delete pop3_client;
        pop3_fail("POP3 Client Authenticate() failed\n");
    }

	if(interactive)
	{
		pop3_start_prompt();
	}

	pop3_client->Pop3Quit();
	
	delete pop3_client;
}
