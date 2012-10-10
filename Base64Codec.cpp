#include "Base64Codec.h"

/*
 * Constructur
 */
B64Codec::B64Codec(){
 // do nothing
}

/*
 * Base64 Codec Implementaton 
 */

string B64Codec::getBitString(char N)
{
string bstr = "";
int mask = (1<<5);
	for(int i=0;i<6;i++,mask>>=1)
		{
			if(N&mask)
				bstr+="1";
			else bstr+="0";	
		}
return bstr;
}

/* get byte stream out of bit string */
vector<char> B64Codec::stringToByteStream(string str)
{
int i=0;
vector<char> byteStream;
while(i < str.length())
	{
		char ch = 0;
		for(int j=0;j<8;j++)
			{
			if(i>=str.length())
				{
				;//cerr<<"Error : Mismatched bytestream size of "<<str.size()<<" B64Codec::stringToByteStream request"<<endl;	
				}
			else {
				ch<<=1;
				ch|=(str[i]=='1');
				}
			i++;
			}
			byteStream.push_back(ch);			
	}
return byteStream;
}

/*
 * Get a vector of bytes from Base64 encoded stream
 */
vector<char> B64Codec::decodeB64Stream(string inp)
	{
		string bstr = "";
		int padding = 0;
		for(int i=0;i< inp.length();i++)
			{
				int curNum = 0;
				if(inp[i]>='A' && inp[i]<='Z')
					curNum = inp[i]-'A';					
				else if(inp[i]>='a' && inp[i]<='z')
					curNum = inp[i]-'a'+26;					
				else if(inp[i]>='0' && inp[i]<='9')
					curNum = inp[i]-'0'+52;
				else if(inp[i] == '+')
					curNum = 62;
				else if(inp[i] == '/')
					curNum = 63;
				else if(inp[i] == '=')
					padding++;				
				else 
					cerr<<"Error : Unknown Base64 character("<<inp[i]<<" in B64Codec::decodeB64Stream request"<<endl;
				bstr+= getBitString(curNum);
			}
		int byteStreamLength = bstr.length();		

		if(padding == 2) /* discard last 16 bits */
			bstr = bstr.substr(0, byteStreamLength - 16);
		else if(padding == 1)	
			bstr = bstr.substr(0, byteStreamLength - 8);

		vector<char> byteStream = stringToByteStream(bstr);
		return byteStream;
	}

string B64Codec::encodeB64Stream(vector<char> seq)
{
	string bstr = "";
	int z = seq.size();
	for(int i=0;i<z;i++)
		{
			int mask = 0x80;
			for(int j=0;j<8;j++, mask>>=1)
				{
				if((mask&seq[i]) != 0)
					bstr += "1";	
				else
					bstr += "0";
				}
		}
	while(bstr.length()%6 != 0)
		bstr += "0";
	
	int pad = 0;
	if(z%3==1)
		pad = 2;
	else if(z%3 == 1) 
		pad = 1;	

	return getEncodingFromBitString(bstr, pad);
}

string B64Codec::getEncodingFromBitString(string str, int plen)
	{
	string base64 = "";
	unsigned int num =0;
	int pos = 0;
	int len = str.length();
		
	while(pos<len)
	{
		num = 0;
		for(int i=0;i<6;i++)
			{	
				num<<=1;
				if(str[pos] == '1') num|=1;
				pos++;
			}
		
			if(num<26)
				base64 += char('A' + num);
			else if(num<52)
				base64 += char('a' + num - 26);
			else if(num < 62 )
				base64 += char('0' + num - 52 );
			else if(num == 62)
				base64 += '+';
			else if(num == 63)
				base64 += '/';
	}

	//cout<<" Made "<<base64.length()<<" chars "<<endl;
	if(plen == 2)
			base64 += "==";
	else if(plen == 1)
			base64 += "=";
return base64;
}
