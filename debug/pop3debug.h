#include <stdio.h>
#include <common/pop3attrs.h>

#ifndef __POP3__DEBUG__H
#define __POP3__DEBUG__H

#ifndef POP3_DEBUG_LEVEL
#define POP3_DEBUG_LEVEL 1
#endif

namespace pop3
{
	namespace pop3debug
    {
        enum
        {
            POP3_DEBUG_SEVERE,
            POP3_DEBUG_CONN,
            POP3_DEBUG_INTERNAL,
			POP3_DEBUG_AUTH,
            POP3_DEBUG_WARN,
            POP3_DEBUG_INFO1,
            POP3_DEBUG_INFO2,
            POP3_DEBUG_PRIV,
			POP3_DEBUG_MD5_DATA,
			POP3_DEBUG_BASE64_DATA
        };
    }

	const string DEBUG_LEVEL_STRING[] = 
	{
		"SEVR",
		"CONN",
		"INTL",
		"AUTH",
		"WARN",
		"INF1",
		"INF2",
		"PRIV",
		"MD5-DATA",
		"BASE64-DATA"
	};

	inline void POP3_DEBUG(const unsigned int level, const char* format, ...) check_format(printf, 2, 3);
	inline void POP3_DEBUG(const unsigned int level, const char* format, ...)
	{
		if(level <= POP3_DEBUG_LEVEL)
		{
			printf("pop3client: %s :", DEBUG_LEVEL_STRING[level].c_str());
			va_list args;
			va_start(args, format);
			vprintf(format, args);
			va_end(args);
		}
	}

	//Wrapper MACROs
	#define POP3_DEBUG_SEVERE(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_SEVERE, x, ##__VA_ARGS__)

	#define POP3_DEBUG_CONN(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_CONN, x, ##__VA_ARGS__)

	#define POP3_DEBUG_INTERNAL(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_INTERNAL, x, ##__VA_ARGS__)

	#define POP3_DEBUG_AUTH(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_AUTH, x, ##__VA_ARGS__)

	#define POP3_DEBUG_WARN(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_WARN, x, ##__VA_ARGS__)

	#define POP3_DEBUG_INFO1(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_INFO1, x, ##__VA_ARGS__)

	#define POP3_DEBUG_INFO2(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_INFO2, x, ##__VA_ARGS__)

	#define POP3_DEBUG_PRIV(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_PRIV, x, ##__VA_ARGS__)

	#define POP3_DEBUG_MD5_DATA(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_MD5_DATA, x, ##__VA_ARGS__)

	#define POP3_DEBUG_BASE64_DATA(x,...)\
		POP3_DEBUG(pop3debug::POP3_DEBUG_BASE64_DATA, x, ##__VA_ARGS__)
}

#endif
