#include "Base64Codec.h"
#include<string>
#include<vector>
#include<iostream>
using namespace std;

string getBitStr(char N)
{
string bstr = "";
int mask = (1<<7);
        for(int i=0;i<8;i++,mask>>=1)
                {
                        if(N&mask)
                                bstr+="1";
                        else bstr+="0";
                }
return bstr;
}

int main()
{
string inp = string("MIICXAIBAAKBgQDNL8HdXOazYFh3Smk+bp6j4UmuXcH5DRVIKCkAXCDnJtpmTfxT") +
string("/nP/x1Dx/JO5Z/BGamdavUsdbVTy6q6Wd58lrfPvlRSnpZkhV7NUigp/gMrSWn1D") +
string("9r13/8A8GhBNcc5ZQNEVRIcjw/G0HTfYZeczJwqly9H6azYe65Qv7CWi+QIDAQAB") +
string("AoGAVD6zfkvSfPul1vS6WWPZxreNJQZhyfvRLRswGnG5IK8XJMIIRARJZE9VsMVf") +
string("cdR3FrJBVUQ7Pw3QvxwUKrtan8WG1gLoNQ415Y/wrz4DPvgskQG2hRyE4Drq8dS5") +
string("rbK0oSyJ7wQjKFO89b4nIm04SZXgTCb+YjxG6xZtNDsUarECQQDtXH1PDrynReYd") +
string("ulqwszKCh9K66eT/cL7Tgj2/OEHVKr6BpkXij57DvyMqBA9w1H0z4uku26GuBvsu") +
string("SdRmVkl/AkEA3Ux7MzPZ9aiN3aDY1EGGC0f4+uAj6bHn8fLnGyS+DQh9sv94ED2m") +
string("zf1tL6oOZ8juq44Cy12xpk0/ZJ4+rIGfhwJAcV6Jo2cAiEyEepJ1mowcheflqMzq") +
string("SW9KVa+RWnG+T9hYoYgPPQUn6Yqzeu/xiAyVuGCay3yvnnVLJ3Kv9ikkdQJAAiyy") +
string("OTqVNbjGTBs8hjlum8XFSJHTSISbBuGgK8AcrfwbYBrqjx5L+VI4NHOzWIm87qqi") +
string("lGUDTeMMcGytqPxNGQJBAKwSRHZfwt0JCiPjT9zMqH6Tpj05Y2s6e7BMBf9Wfatr") +
string("0ou3RF7H+a9w5UTx6UES66L9jGvZXk44Zs6z1UVII3M="); /* input base64 string */

B64Codec testCodec = B64Codec();

vector<char> bytestream = testCodec.decodeB64Stream(inp);
cout<<" Size of Byte stream is "<<bytestream.size()<<endl;

int pos = 0;
char curByte = bytestream[pos];

cout<<getBitStr(curByte)<<" : "<<int(curByte)<<endl;

if((curByte&(1<<7)) || (curByte&(1<<6)));
else 
	cout<<" Universal "<<endl;

cout<<"Tag number is "<<int(curByte&(0x1F))<<endl;

pos++;
curByte = bytestream[pos];

cout<<"Length Octect#1 is "<<getBitStr(curByte)<<endl;;

if(curByte & 0x80)
	cout<<" Sequence is in Long form"<<endl;
else 
	cout<<" Sequence in Short Form "<<endl;

cout<<"Length Octect#1 is "<<getBitStr(curByte)<<endl;;

cout<<"Test Val is "<<getBitStr(curByte&0x7F)<<endl;;

char lengthOfSeq = ( curByte & 0x7F );
cout<<"LenField in length octet#1 is "<<int(lengthOfSeq)<<" : "<<getBitStr(lengthOfSeq)<< endl;

int actualFieldLength = 0;
pos++;
curByte = bytestream[pos];
actualFieldLength |= curByte;
actualFieldLength<<=8;

pos++;
curByte = bytestream[pos];
actualFieldLength |= curByte;
pos++;

cout<<"We need to look at "<<actualFieldLength<<" more bytes"<<endl;
cout<<"Looked at "<<pos <<" bytes out of "<<bytestream.size()<<" total bytes"<<endl;
return 0;
}
