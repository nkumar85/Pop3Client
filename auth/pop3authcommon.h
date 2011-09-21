#ifndef __POP3__AUTH__COMMON__H
#define __POP3__AUTH__COMMON__H

#include "common/pop3base64.h"
#include "common/pop3md5.h"

namespace pop3
{
	class Pop3AuthCommon
	{
		private:
			static void DoBase64(const string& input, string& output, const bool op);

		public:
			static void Base64Decode(const string& input, string& output);
			static void Base64Encode(const string& input, string& output);
			static void Md5Byte(const string& input, UCHAR* output);
			static void Md5String(const string& input, string& output, const bool md5_case);
			static void HmacMd5Byte(const string& data, const string& key, UCHAR* output);
			static void HmacMd5String(const string& data, const string& key, string& output, const bool md5_case);
	};
}

#endif
