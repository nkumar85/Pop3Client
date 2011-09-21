#include "pop3commons.h"
#include "debug/pop3debug.h"
//#include "pop3defs.h"

#ifndef __POP3UTILS__H
#define __POP3UTILS__H

#define POP3_FAIL(x,y)\
	POP3_DEBUG(x);\
	return y;

#define POP3_SUCCESS(x,y)\
	POP3_DEBUG(x);\
	return y;

namespace pop3
{
	using namespace std;

	template<class source, class dst>
		bool pop3_value_cast(const source& from, dst& to);

	template<class T>
		bool pop3_type_to_string(const T& value, string& str);

	template<class T>
		bool pop3_string_to_type(const string& str, T& value);

	template<typename T1, typename T2>
		void pop3_break_string2(const string& str_val, T1& value1, T2& value2, const char delim);

	void pop3_break_string2(const string& str_val, string& value1, string& value2, const char delim);

	void pop3_remove_crlf(string& value);

	void pop3_trim(string& value, char start, char end, bool include = false);

	bool pop3_string_compare(const string& s1, const string& s2, bool case_sensitive=false);

	void pop3_trim_ws(string& data);

	/* NET utils */
	int pop3_ip_to_string(const struct sockaddr* ipaddr, string& value);
	
	struct sockaddr* pop3_string_to_ip(const string& ip_str);

	int pop3_ip_to_host(const struct sockaddr* ip_addr, const socklen_t ip_len, bool fqdn, string& host_name);

	bool pop3_is_link_local_ip(const struct sockaddr* ip_addr);
}

#endif
