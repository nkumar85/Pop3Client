#include "pop3strtoken.h"

namespace pop3
{
	bool StringTokenizer::has_more_tokens()
	{
		if(!temp)
		{
			return false;
		}

		word = init?(strtok_r(0, delim.c_str(), &brkb)):(strtok_r(temp, delim.c_str(), &brkb));
		init = true;

		if(word != NULL && strcmp(word, end.c_str()) != 0)
		{
			return true;
		}

		return false;
	}

	void StringTokenizer::next_token(string& data)
	{
		data = word;
	}

	void StringTokenizer::tokenize(vector<string>& container)
	{
		while(has_more_tokens())
		{
			string data;
			next_token(data);
			container.push_back(data);
		}
	}
}
