#include<gmpxx.h>
#include<iostream>
#include<sstream>
#include<vector>
using namespace std;

int getHexVal(char ch){
	int i = 0;
	if(ch >= '0' && ch<='9')
		i = ch - '0';
	else if(ch>='A'&&ch<='Z')
		i = ch - 'A' + 10;
	else 
		i = ch - 'a' + 10;
	return i;
}

vector<char> getByteStream(mpz_class num, int len)
{
	stringstream ss1;
	ss1<<hex<<num;
	string hexNum = ss1.str();	
	
	int padding = 2*len - hexNum.length();
	for(int i=0;i<padding;i++)
		hexNum = "0" + hexNum;
	
	vector<char> byteStream;
	int pos = 0;
	for(int i=0;i<len;i++)
		{
			char ch = 0 ;
			ch |= getHexVal(hexNum[pos]);
			ch<<=4; pos++;
			ch|=getHexVal(hexNum[pos]);
			pos++;
			byteStream.push_back(ch);			
		}
	return byteStream;
}

int main()
{
mpz_class a = mpz_class("4545", 16);
cout<<hex<<a<<endl;
vector<char> bstream = getByteStream(a, 2);

for(int i=0;i<bstream.size();i++)
	cout<<bstream[i];	
return 0;
}
