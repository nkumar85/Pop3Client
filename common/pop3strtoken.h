#include "pop3commons.h"

#ifndef __POP3__STRTOKEN__H
#define __POP3__STRTOKEN__H

namespace pop3
{
	using namespace std;
	class StringTokenizer
	{
		private:
			char *temp, *word, *brkb;;
			string delim, end;
			bool init;

		public:
			StringTokenizer(const string& data, const string& delimiter, const string& endstr)
							:temp(strdup(data.c_str())), word(0), brkb(0), delim(delimiter), end(endstr), init(false)
			{
			}
			~StringTokenizer()
			{
				if(temp) 
				{
					free(temp);
					temp = NULL;
				}
			}
			void tokenize(vector<string>& container);
			bool has_more_tokens();
			void next_token(string& data);			
	};
}

#endif
