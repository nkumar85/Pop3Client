#include "pop3authcommon.h"

namespace pop3
{
	void Pop3AuthCommon::Base64Decode(const string& input, string& output)
	{
		DoBase64(input, output, true);
	}

	void Pop3AuthCommon::Base64Encode(const string& input, string& output)
	{
		DoBase64(input, output, false);
	}

	void Pop3AuthCommon::Md5Byte(const string& input, UCHAR* output)
	{
		MD5* md5 = MD5::GetInstance();
		md5->Md5Update(reinterpret_cast<UCHAR*>(const_cast<char*>(input.c_str())), input.length());
		md5->Md5Final(output);
		delete md5;
	}

	void Pop3AuthCommon::Md5String(const string& input, string& output, const bool md5_case)
	{
		UCHAR output2[16] = {0};
		Md5Byte(input, output2);
		MD5::Md5HexString(output2, output, md5_case);
	}

	void Pop3AuthCommon::HmacMd5Byte(const string& data, const string& key, UCHAR* output)
	{
		HMAC_MD5* md5 = HMAC_MD5::GetInstance();
		md5->HmacMd5Digest(reinterpret_cast<UCHAR*>(const_cast<char*>(data.c_str())),
								data.length(),
								reinterpret_cast<UCHAR*>(const_cast<char*>(key.c_str())),
								key.length(),
								output);
		delete md5;
	}

	void Pop3AuthCommon::HmacMd5String(const string& data, const string& key, string& output, const bool md5_case)
	{
		UCHAR output2[16] = {0};
		HmacMd5Byte(data, key, output2);
		MD5::Md5HexString(output2, output, md5_case);	
	}

	void Pop3AuthCommon::DoBase64(const string& input, string& output, const bool op)
	{
		Base64* base64 = Base64::GetInstance();
		int outputSize = 0;
		int inputSize = input.length();
		char* buffer;
		if(op)
		{
			outputSize = base64->GetDecodeLength(inputSize);
			buffer = new char[outputSize];
			bzero(buffer, outputSize);
			base64->Decode(input.c_str(), inputSize, buffer, outputSize);
			output.assign(buffer, outputSize);
		}
		else
		{
			outputSize = base64->GetEncodeLength(inputSize);
			buffer = new char[outputSize+1];
			bzero(buffer, outputSize+1);
			base64->Encode(input.c_str(), inputSize, buffer);
			buffer[outputSize] = '\0';
			output.assign(buffer, outputSize);
		}

		delete[] buffer;
		delete base64;
	}
}
