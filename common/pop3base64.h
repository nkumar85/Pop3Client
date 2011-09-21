/*

Author: HERAMBA
e-mail: heramba85@gmail.com
Description: Base64 encode/decode source.

*/

#ifndef __BASE64__H__
#define __BASE64__H__

#include<map>
#include<stdio.h>
#include<iostream>

namespace pop3
{
	using namespace std;

	typedef enum POP3_BASE64_STATUS
	{
		BASE64_OK,
		BASE64_INVALID_BUF,
		BASE64_INVALID_DATA
	}POP3_BASE64_STATUS_E;

	class Base64
	{
		private:
			static char BASE64_TABLE[65];
			static map<char,int> BASE64_RTABLE;
			static bool create_map();
			static bool dummy;
			Base64(){}
			int GetNumberOfPaddingChars(const int nsiZe) const;		

		public:
			static Base64* GetInstance();
			POP3_BASE64_STATUS_E Encode(const char* data, const int size, char* outputBuffer);
			POP3_BASE64_STATUS_E Decode(const char* data, const int size, char* outputBuffer);
			POP3_BASE64_STATUS_E Decode(const char* data, const int size, char* outputBuffer, int& bytes_converted);
			static int GetEncodeLength(const int nSizeData);
			static int GetDecodeLength(const int nSizebase64);
	};
}

#endif
