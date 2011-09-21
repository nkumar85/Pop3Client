/*
 * Copyright HERAMBA
 * E-mail: heramba85@gmail.com
 * Some part of the code referred from prototype code in RFC-1321 
*/

#include "pop3md5.h"
#include <debug/pop3debug.h>

namespace pop3
{
	/* Constant declarations */
	const UINT MD5::BYTE_MASK = 0x000000ff;

	/*
	 * 'T' array as defined in RFC-1321
	 * T[i] = fabs(sin(i+1)) * 2^32;
	*/
	const UINT MD5::T[64] = 
	{
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	/* 
		PAD BYTES as defined in RFC
		Min - 1 bit padding 
		Max - 512 bits padding

		The message is "padded" (extended) so that its length (in bits) is
		congruent to 448, modulo 512. That is, the message is extended so
		that it is just 64 bits shy of being a multiple of 512 bits long.
		Padding is always performed, even if the length of the message is
		already congruent to 448, modulo 512.

		Padding is performed as follows: a single "1" bit is appended to the
		message, and then "0" bits are appended so that the length in bits of
		the padded message becomes congruent to 448, modulo 512. In all, at
		least one bit and at most 512 bits are appended.
	*/
	UCHAR MD5::PAD_BYTES[64] =
	{
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0
	};

	/* Initial MD5 buffers */
	const UINT MD5::MD5_INIT_SUM[4] =
	{
		0x67452301,
		0xEFCDAB89,
		0x98BADCFE,
		0x10325476
	};

	void MD5::Md5Init()
	{
		this->msg_len = 0;
		this->used_len = 0;
		this->buffer_count = 0;

		this->state[0] = MD5_INIT_SUM[0];
		this->state[1] = MD5_INIT_SUM[1];
		this->state[2] = MD5_INIT_SUM[2];
		this->state[3] = MD5_INIT_SUM[3];
	}

	void MD5::Md5Compute(UINT state[4], UCHAR block[64])
	{
		UINT a=state[0], b=state[1], c=state[2], d=state[3], x[16] = {0};

		byte64_to_int16(block, x);

		/* 
	 		* 
	 		* ROUND - 1
	 		* [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
	 		* [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
	 		* [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
	 		* [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
	 		*
	  	*/
		OP1(a, b, c, d, x[0], 7, T[0]);
		OP1(d, a, b, c, x[1], 12, T[1]);
		OP1(c, d, a, b, x[2], 17, T[2]);
		OP1(b, c, d, a, x[3], 22, T[3]);
		OP1(a, b, c, d, x[4], 7, T[4]);
		OP1(d, a, b, c, x[5], 12, T[5]);
		OP1(c, d, a, b, x[6], 17, T[6]);
		OP1(b, c, d, a, x[7], 22, T[7]);
		OP1(a, b, c, d, x[8], 7, T[8]);
		OP1(d, a, b, c, x[9], 12, T[9]);
		OP1(c, d, a, b, x[10], 17, T[10]);
		OP1(b, c, d, a, x[11], 22, T[11]);
		OP1(a, b, c, d, x[12], 7, T[12]);
		OP1(d, a, b, c, x[13], 12, T[13]);
		OP1(c, d, a, b, x[14], 17, T[14]);
		OP1(b, c, d, a, x[15], 22, T[15]);

		/*
	 		* 
	 		* ROUND - 2
	 		* [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
	 		* [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
	 		* [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
	 		* [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]
	 	*/
		OP2(a, b, c, d, x[1], 5, T[16]);
		OP2(d, a, b, c, x[6], 9, T[17]);
		OP2(c, d, a, b, x[11], 14, T[18]);
		OP2(b, c, d, a, x[0], 20, T[19]);
		OP2(a, b, c, d, x[5], 5, T[20]);
		OP2(d, a, b, c, x[10], 9, T[21]);
		OP2(c, d, a, b, x[15], 14, T[22]);
		OP2(b, c, d, a, x[4], 20, T[23]);
		OP2(a, b, c, d, x[9], 5, T[24]);
		OP2(d, a, b, c, x[14], 9, T[25]);
		OP2(c, d, a, b, x[3], 14, T[26]);
		OP2(b, c, d, a, x[8], 20, T[27]);
		OP2(a, b, c, d, x[13], 5, T[28]);
		OP2(d, a, b, c, x[2], 9, T[29]);
		OP2(c, d, a, b, x[7], 14, T[30]);
		OP2(b, c, d, a, x[12], 20, T[31]);

		/*
	 		* 
	 		* ROUND - 3
	 		* [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
	 		* [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
	 		* [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
	 		* [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]
	 		*
	 	*/
		OP3(a, b, c, d, x[5], 4, T[32]);
		OP3(d, a, b, c, x[8], 11, T[33]);
		OP3(c, d, a, b, x[11], 16, T[34]);
		OP3(b, c, d, a, x[14], 23, T[35]);
		OP3(a, b, c, d, x[1], 4, T[36]);
		OP3(d, a, b, c, x[4], 11, T[37]);
		OP3(c, d, a, b, x[7], 16, T[38]);
		OP3(b, c, d, a, x[10], 23, T[39]);
		OP3(a, b, c, d, x[13], 4, T[40]);
		OP3(d, a, b, c, x[0], 11, T[41]);
		OP3(c, d, a, b, x[3], 16, T[42]);
		OP3(b, c, d, a, x[6], 23, T[43]);
		OP3(a, b, c, d, x[9], 4, T[44]);
		OP3(d, a, b, c, x[12], 11, T[45]);
		OP3(c, d, a, b, x[15], 16, T[46]);
		OP3(b, c, d, a, x[2], 23, T[47]);

		/*
	 		* 
	 		* ROUND - 4
	 		* [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
	 		* [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
	 		* [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
	 		* [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]
	 		*
	 	*/
		OP4(a, b, c, d, x[0], 6, T[48]);
		OP4(d, a, b, c, x[7], 10, T[49]);
		OP4(c, d, a, b, x[14], 15, T[50]);
		OP4(b, c, d, a, x[5], 21, T[51]);
		OP4(a, b, c, d, x[12], 6, T[52]);
		OP4(d, a, b, c, x[3], 10, T[53]);
		OP4(c, d, a, b, x[10], 15, T[54]);
		OP4(b, c, d, a, x[1], 21, T[55]);
		OP4(a, b, c, d, x[8], 6, T[56]);
		OP4(d, a, b, c, x[15], 10, T[57]);
		OP4(c, d, a, b, x[6], 15, T[58]);
		OP4(b, c, d, a, x[13], 21, T[59]);
		OP4(a, b, c, d, x[4], 6, T[60]);
		OP4(d, a, b, c, x[11], 10, T[61]);
		OP4(c, d, a, b, x[2], 15, T[62]);
		OP4(b, c, d, a, x[9], 21, T[63]);

		state[0] += a;
		state[1] += b;
		state[2] += c;
		state[3] += d;

		POP3_DEBUG(pop3debug::POP3_DEBUG_MD5_DATA, "State : %x %x %x %x\n", state[0], state[1], state[2], state[3]);
	}

	void MD5::Md5Update(UCHAR* input, UINT inputLen)
	{
		UINT num_iter = 0, buf_count = 0;
		
		//Number of 64 byte chunks
		num_iter = (this->buffer_count + inputLen) >> 6;

		//Number of remaining bytes after 64 byte chunking
		buf_count = (this->buffer_count + inputLen) - (num_iter << 6);

		UINT j=0;
		for(UINT i=0; i<num_iter; i++)
		{
			memcpy(&this->buffer[this->buffer_count], &input[j], 64-this->buffer_count); 
			Md5Compute(this->state, this->buffer);
			this->buffer_count = 0;
			j += 64;
			this->used_len += 64;
		}
		j = num_iter > 0?(inputLen - buf_count):0;

		this->msg_len += inputLen;
		size_t size = msg_len-used_len;

	    //Prevent memory corruption
	    if(size+buffer_count > 64)
	        size = size-buffer_count;

		memcpy(&this->buffer[this->buffer_count], &input[j], size);
		this->buffer_count = buf_count;
	}

	void MD5::Md5Final(UCHAR* digest_sum)
	{
		UINT padding = (this->buffer_count < 56)?(56 - this->buffer_count):(120 - this->buffer_count);
		//printf("Padding = %u\n", padding);
		UINT64 size = this->msg_len;
		//printf("Size = %u\n", size);
		UCHAR size_bits[8];
		Md5Update(PAD_BYTES, padding);
		int64_to_byte8((size << 3), size_bits);
		Md5Update(size_bits, 8);

		//4 32 bit integers to 16 bytes conversion
		int4_to_byte16(state, digest_sum);
	}

	void MD5::Md5HexString(const UCHAR* hex_out, string& str_out, const bool lower_case)
	{
		UINT8 hash_len = 16;
		string format = lower_case ? "%02x" : "%02X";
		uint16_t str_len = (hash_len << 2) + 1;
		char* output = (char*)(alloca(str_len));
		bzero(output, str_len);

		for(int i = 0, j = 0; i < hash_len; i++, j += 2)
		{
			sprintf(output+j, format.c_str(), hex_out[i]);
		}

		str_out = output;
	}

	void MD5::Md5Reset()
	{
		Md5Init();
	}

	void HMAC_MD5::HmacMd5Digest(UCHAR* data, UINT data_len,
						UCHAR* key, UINT key_len, UCHAR* output)
	{
		UCHAR i_pad[64] = {0};
	    UCHAR o_pad[64] = {0};

		/* If the key is more than 64 bytes, we need to md5 the key and set key length to 16 */
		if(key_len > 64)
	    {
	        md5->Md5Update(key, key_len);
	        md5->Md5Final(output);
	        key_len = 16;
	        memcpy(key, output, 16);
	    }

		//Copy the key to inner pad and outer pad buffers
		memcpy(i_pad, key, key_len);
		memcpy(o_pad, key, key_len);

		/*
			* Do the operation as specified in RFC
			* ipad = the byte 0x36 repeated B times
			* opad = the byte 0x5C repeated B times.
		*/
	    for(UINT i=0; i<64; i++)
	    {
			//IPAD = K XOR opad
	        i_pad[i] ^= 0x36;

			//OPAD = K XOR ipad
	        o_pad[i] ^= 0x5c;
	    }

		/* 
			Final output is = MD5(OPAD, MD5(IPAD, data))
		*/ 
		
		// inner = MD5(IPAD, data)
	    md5->Md5Reset();
	    md5->Md5Update(i_pad, 64);
	    md5->Md5Update(data, data_len);
	    md5->Md5Final(output);

		// output = MD5(OPAD, inner)
		md5->Md5Reset();
		md5->Md5Update(o_pad, 64);
		md5->Md5Update(output, 16);
		md5->Md5Final(output);
	}
}
