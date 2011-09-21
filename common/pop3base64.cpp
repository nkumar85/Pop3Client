/*

Author: HERAMBA
e-mail: heramba85@gmail.com
Description: Base64 encode/decode source.

*/

#include "pop3base64.h"

namespace pop3
{
	char Base64::BASE64_TABLE[65] =
	{
    	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '='
	};

	bool Base64::create_map()
	{
		char c = 'A';
		int i = 0;
	
		for(;i<62;i++)
		{
			BASE64_RTABLE[c]=i;
			c++;
			if(c == 'Z')
			{
				i++;
				BASE64_RTABLE[c]=i;
				c = 'a';
				continue;
			}
			if(c == 'z')
			{
				i++;
				BASE64_RTABLE[c]=i;
				c = 0x30;
				continue;
			}
		}
			
		BASE64_RTABLE['+'] = 62;
		BASE64_RTABLE['/'] = 63;
		BASE64_RTABLE['='] = 64;

		return true;
	}

	map<char,int> Base64::BASE64_RTABLE;
	bool Base64::dummy = Base64::create_map();

	Base64* Base64::GetInstance()
	{
		return new Base64();
	}

	int Base64::GetEncodeLength(const int nSizeData)
	{
		return ((nSizeData/3) << 2) + ((nSizeData%3)==0?0:4);
	}

	int Base64::GetDecodeLength(const int nSizeData)

	{
		return ((nSizeData * 3) >> 2);
	}

	int Base64::GetNumberOfPaddingChars(const int nSize) const
	{
		int rem = nSize%3;
		return (rem==0?0:3-rem);
	}

	POP3_BASE64_STATUS_E Base64::Encode(const char* data, const int size, char* outputBuffer)
	{
		if(!data)
			return BASE64_INVALID_BUF;

		if(size <= 0)
			return BASE64_OK;

		int i = 0, j = 0, iter = size - (size%3);
		unsigned char c;
		int k = GetNumberOfPaddingChars(size);

		while(i < iter)
		{
			c = (((unsigned char)data[i]) >> 2) & 0x3F;
			outputBuffer[j] = BASE64_TABLE[c];

			c = ((((unsigned char)data[i]) << 4) & 0x30) | (((unsigned char)data[i+1]) >> 4);
			outputBuffer[j+1] = BASE64_TABLE[c];

   			c = ((((unsigned char)data[i+1]) << 2) & 0x3C) | (((unsigned char)data[i+2]) >> 6);
			outputBuffer[j+2] = BASE64_TABLE[c];

   			c = ((unsigned char)data[i+2]) & 0x3F;
			outputBuffer[j+3] = BASE64_TABLE[c];
		
			i += 3;
			j += 4;
		}
		if(k)
		{
			c = (data[i] >> 2) & 0x3F;
			outputBuffer[j]= BASE64_TABLE[c];

			c = (i+1)<size?(((unsigned char)data[i] << 4) & 0x30) | ((unsigned char)data[i+1] >> 4):(((unsigned char)data[i] << 4) & 0x30);
			outputBuffer[j+1] = BASE64_TABLE[c];

			c = (i+2)==size?(((unsigned char)data[i+1] << 2) & 0x3C):64;
			outputBuffer[j+2] = BASE64_TABLE[c];

			outputBuffer[j+3] = BASE64_TABLE[64];

			j += 4;
		}

		return BASE64_OK;
	}

	POP3_BASE64_STATUS_E Base64::Decode(const char* data, const int size, char* outputBuffer)
	{
		int bytes_converted = 0;
		return Decode(data, size, outputBuffer, bytes_converted);
	}

	POP3_BASE64_STATUS_E Base64::Decode(const char* data, const int size, char* outputBuffer, int& bytes_converted)
	{
		if(!data)
		{
			return BASE64_INVALID_BUF;
		}

		if(size % 4 != 0)
		{
			return BASE64_INVALID_DATA;
		}

		int i = 0, j=0, iter = size-4;
		bytes_converted = 0;

		while(j < iter)
		{
			//Check if the character is valid base64
			outputBuffer[i] = ((BASE64_RTABLE[data[j]] << 2)& (unsigned char)0xFC)|((BASE64_RTABLE[data[j+1]] >> 4)&0x03);
			outputBuffer[i+1] = ((BASE64_RTABLE[data[j+1]] << 4)& (unsigned char)0xF0)|((BASE64_RTABLE[data[j+2]] >> 2)&0x0F);
			outputBuffer[i+2] = ((BASE64_RTABLE[data[j+2]] << 6)&(unsigned char)0xC0)|(BASE64_RTABLE[data[j+3]]);
			i += 3;
			j += 4;
		}

		//last 4 bytes check
		outputBuffer[i] = ((BASE64_RTABLE[data[j]] << 2)& (unsigned char)0xFC)|((BASE64_RTABLE[data[j+1]] >> 4)&0x03);
		if(data[j+2] != '=')
		{
			i++;
			outputBuffer[i] = ((BASE64_RTABLE[data[j+1]] << 4)& (unsigned char)0xF0)|((BASE64_RTABLE[data[j+2]] >> 2)&0x0F);
		}
		if(data[j+3] != '=')
		{
			i++;
			outputBuffer[i] = ((BASE64_RTABLE[data[j+2]] << 6)& (unsigned char)0xC0)|(BASE64_RTABLE[data[j+3]]);
		}

		bytes_converted = i+1;

		return BASE64_OK;
	}
}
