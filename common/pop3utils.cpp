#include "pop3utils.h"

namespace pop3
{
	using namespace std;

	template bool pop3_type_to_string(const unsigned int& value, string& str);
	template bool pop3_type_to_string(const unsigned long long& value, string& str);
	template bool pop3_string_to_type(const string& str, unsigned int& value);
	template bool pop3_string_to_type(const string& str, int& value);
	template void pop3_break_string2(const string& str_val, unsigned int& value1, string& value2, const char delim);
	template void pop3_break_string2(const string& str_val, unsigned int& value1, unsigned int& value2, const char delim);
	template void pop3_break_string2(const string& str_val, string& value1, string& value2, const char delim);

	template<class source, class dst>
		bool pop3_value_cast(const source& from, dst& to)
	{
		stringstream stream;
		stream<<from;
		stream>>to;
/*
		if(!stream.eof())
		{
			return false;
		}

		return true;		
*/
		return stream.eof();
	}

	template<class T>
		bool pop3_type_to_string(const T& value, string& str)
	{
		return pop3_value_cast(value, str);
	}

	template<class T>
		bool pop3_string_to_type(const string& str, T& value)
	{
		return pop3_value_cast(str, value);
	}

	template<typename T1, typename T2>
		void pop3_break_string2(const string& str_val, T1& value1, T2& value2, const char delim)
	{
		size_t index = str_val.find(delim);
		string key, value;

		if(index != string::npos)
		{
			key = str_val.substr(0, index);
			value = str_val.substr(index + 1, str_val.length() - index);
		}
		else
		{
			key = str_val.substr(0, index);
			value = "";
		}

		pop3_string_to_type(key, value1);
		pop3_string_to_type(value, value2);
	}

	void pop3_break_string2(const string& str_val, string& value1, string& value2, const char delim)
	{
		size_t index = str_val.find(delim);
		string key, value;

		if(index != string::npos)
		{
			key = str_val.substr(0, index);
			value = str_val.substr(index + 1, str_val.length() - index);
		}
		else
		{
			key = str_val.substr(0, index);
			value = "";
		}

		value1 = key;
		value2 = value;
	}

	void pop3_remove_crlf(string& value)
	{
		size_t index = value.find_first_of("\r\n");
		if(index != string::npos)
			value = value.substr(0, index);
	}

	void pop3_trim(string& value, char start, char end, bool include)
	{
		size_t index1 = 0, index2 = value.length()-1;
		if(value == "")
		{
			return;
		}

		index1 = ((index1 = value.find_last_of(start)) == string::npos)?string::npos:index1;
		index2 = ((index2 = value.find_first_of(end)) == string::npos)?value.length()-1:index2;
	
		if(index1 == string::npos)
		{
			return;
		}

		if(index1 < index2)
			value = include?value.substr(index1, index2-index1+1):value.substr(index1+1, index2-index1-1);
		else
			value = include?value.substr(index2, index1-index2+1):value.substr(index2+1, index1-index2-1);
	}

	int pop3_ip_to_string(const struct sockaddr* ipaddr, string& value)
	{
		char buffer[INET6_ADDRSTRLEN] = {0};
		int af_family = ipaddr->sa_family;

		if(af_family == AF_INET)
		{
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)ipaddr;
			const char* p = inet_ntop(ipaddr->sa_family, &(ipv4->sin_addr), buffer, sizeof(struct sockaddr_in));
			if(p == 0)
			{
				POP3_DEBUG(pop3debug::POP3_DEBUG_WARN, "Error converting ipv4 address");
				goto err;
			}
			goto success;
		}
		else if(af_family == AF_INET6)
		{
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)ipaddr;
			const char* p = inet_ntop(ipaddr->sa_family, &(ipv6->sin6_addr), buffer, sizeof(struct sockaddr_in6));
			if(p == 0)
			{
				POP3_DEBUG(pop3debug::POP3_DEBUG_WARN, "Error converting ipv6 address");
				goto err;
			}
			goto success;
		}
		else
		{
			POP3_DEBUG(pop3debug::POP3_DEBUG_WARN, "Unsupported family");			
		}

		err:
			return -1;

		success:	
			value = buffer;

		return 0;
	}

	struct sockaddr* pop3_string_to_ip(const string& ip_str)
	{
		return NULL;
	}

	int pop3_ip_to_host(const struct sockaddr* ip_addr, const socklen_t ip_len, bool fqdn, string& host_name)
	{
		char host[NI_MAXHOST];
		int err = 0;
		int flags = fqdn?0:NI_NOFQDN;

		if ((err = getnameinfo(ip_addr, ip_len, host, sizeof(host),NULL, 0, flags)) == 0)
		{
			host_name = host;
			POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, "%s: resolved ip address to host=%s\n", __func__, host);		
			return 0;
		}

		POP3_DEBUG(pop3debug::POP3_DEBUG_WARN, "%s: error in resolution -- %s\n", __func__, gai_strerror(err));
		return -1;
	}

	bool pop3_is_link_local_ip(const struct sockaddr* sock)
	{
		if(sock->sa_family != AF_INET6)
		{
			return false;
		}

		struct sockaddr_in6 *temp= (struct sockaddr_in6*)(sock);
		return IN6_IS_ADDR_LINKLOCAL(&temp->sin6_addr);
	}
}
