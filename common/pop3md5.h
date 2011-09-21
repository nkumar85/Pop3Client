/*
 * Copyright HERAMBA
 * E-mail: heramba85@gmail.com
 * Description: md5 header file
 * Some part of the code referred from prototype code in RFC-1321
*/

#include "pop3commons.h"

#ifndef __MD5__H
#define __MD5__H

namespace pop3
{
	class MD5
	{
		/* Constants */
		static const UINT BYTE_MASK;
		static const UINT T[64];
		static UCHAR PAD_BYTES[64];
		static const UINT MD5_INIT_SUM[4];

		UINT buffer_count;
		UINT64 msg_len;
		UINT64 used_len;
		UINT state[4];
		UCHAR buffer[64];

		/*
		 * 	Left rotation is part of md5 operation
		 * 	we do not have '<<<' operator in c++.
		*/
		inline UINT LR(UINT num, UINT n)
		{
			return ( (num << n) | (num >> (32 - n)));
		}

		/*
		 *	F(X,Y,Z) = XY v not(X) Z
		*/
		inline UINT F(UINT x, UINT y, UINT z)
		{
			return ((x & y) | ((~x) & z));
		}

		/*
		 *	G(X,Y,Z) = XZ v Y not(Z)
		*/
		inline UINT G(UINT x, UINT y, UINT z)
		{
			return ((x & z) | (y & (~z)));
		}

		/*
		 *	H(X,Y,Z) = X xor Y xor Z
		*/
		inline UINT H(UINT x, UINT y, UINT z)
		{
			return (x ^ y ^ z);
		}

		/*
		 *	I(X,Y,Z) = Y xor (X v not(Z))
		*/
		inline UINT I(UINT x, UINT y, UINT z)
		{
			return (y ^ (x | (~z)));
		}

		/*
		 *
		 * Round - 1
		 * Let [abcd k s i] denote the operation
		 * a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s)
		 *
		*/
		inline void OP1(UINT& a, UINT b, UINT c, UINT d, UINT Xk, UINT s, UINT Ti)
		{
			a = (b + LR((a + F(b,c,d) + Xk + Ti), s));
		}

		/*
	 	*
		 * Round - 2
		 * Let [abcd k s i] denote the operation
		 * a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s)
		 *
		*/
		inline void OP2(UINT& a, UINT b, UINT c, UINT d, UINT Xk, UINT s, UINT Ti)
		{
			a = (b + LR((a + G(b,c,d) + Xk + Ti), s));
		}

		/*
		 *
		 * Round - 3
		 * Let [abcd k s i] denote the operation
		 * a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s)
		 *
		*/
		inline void OP3(UINT& a, UINT b, UINT c, UINT d, UINT Xk, UINT s, UINT Ti)
		{
			a = (b + LR((a + H(b,c,d) + Xk + Ti), s));
		}

		/*
		*
		* Round - 4
		* Let [abcd k s i] denote the operation
		* a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s)
		*
		*/
		inline void OP4(UINT& a, UINT b, UINT c, UINT d, UINT Xk, UINT s, UINT Ti)
		{
			a = (b + LR((a + I(b,c,d) + Xk + Ti), s));
		}

		/*
		 *	Each 64 byte of message is considered as 16 integers and they are operated for md5 sum
		 *	Convert 64 bytes of message to 16 integers
		*/
		inline void byte64_to_int16(const UCHAR* input, UINT* output)
		{
			for(int i=0, j=0; i<16; i++, j+=4)
			{
				output[i] = (((UINT)input[j]) | (((UINT)input[j+1]) << 8) | (((UINT)input[j+2]) << 16) | (((UINT)input[j+3]) << 24));
			}

			/*for (int i=0; i<16; i++)
			{
				printf("%x\n", output[i]);
			}*/
		}

		/*
		 * Once operation is done convert resulting integers to byte format with lower being first
		 * input is buffer of 4 unsigned integers
		 * output is buffer of 16 unsigned chars
		*/
		inline void int4_to_byte16(const UINT* input, UCHAR* output)
		{
			for(int i=0, j=0; i < 4; i++, j+=4)
			{
				output[j] = (UCHAR)(input[i] & BYTE_MASK);
				output[j+1] = (UCHAR)((input[i] >> 8) & BYTE_MASK);
				output[j+2] = (UCHAR)((input[i] >> 16) & BYTE_MASK);
				output[j+3] = (UCHAR)((input[i] >> 24) & BYTE_MASK);
			}
		}

		inline void int64_to_byte8(const UINT64 input, UCHAR* output)
		{
			output[0] = input & BYTE_MASK;
			output[1] = (input >> 8) & BYTE_MASK;
			output[2] = (input >> 16) & BYTE_MASK;
			output[3] = (input >> 24) & BYTE_MASK;
			output[4] = (input >> 32) & BYTE_MASK;
			output[5] = (input >> 40) & BYTE_MASK;
			output[6] = (input >> 48) & BYTE_MASK;
			output[7] = (input >> 56) & BYTE_MASK;
		}

		/* MD5 APIs */

		/*
			Initialize the buffers
		*/
		void Md5Init();

		/*
		 * MD5 transformation logic
		*/
		void Md5Compute(UINT state[4], UCHAR block[64]);

		MD5()
		{
			Md5Init();
		}

	public:

		static MD5* GetInstance()
		{
			return new MD5();
		}

		/*
			Update the md5 sum for the current byte chunk
		*/
		void Md5Update(UCHAR* input, UINT inputLen);

		/*
			Do padding stuff and calculate md5 for remainig bytes
			Gives the current sum as 16 byte data. Argument should have at least 16bytes of size
		*/
		void Md5Final(UCHAR* digest_sum);

		/* Provides string representation of md5-sum*/
		static void Md5HexString(const UCHAR* hex_out, string& str_out, const bool lower_case);

		/*
			Reset the md5 state to have fresh calculation
		*/
		void Md5Reset();	
	};

	class HMAC_MD5
	{
		private:
			MD5* md5;
			HMAC_MD5()
			{
				md5 = MD5::GetInstance();
			}
		public:
			static HMAC_MD5* GetInstance()
			{
				return new HMAC_MD5();
			}
			void HmacMd5Digest(UCHAR* data, UINT datalen, UCHAR* key, UINT key_len, UCHAR* output);
	};
}
#endif
