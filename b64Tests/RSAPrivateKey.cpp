#include "RSAPrivateKey.h"
#include<iostream>
using namespace std;

/* Temporary function. remove it once done */
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

/* Get the Tag */
int RSAPrivateKey::getTag(vector<char> byteStream, int &pos){

	char curByte = byteStream[pos];
	cout<<getBitStr(curByte)<<" : "<<int(curByte)<<endl;
	
if((curByte&(1<<7)) || (curByte&(1<<6)));
else
        cout<<" Universal "<<endl;

	int tag = curByte&(0x1F);
	pos++;
	cout<<"Tag number is "<<tag<<" and pos is "<<pos<<endl;
	return tag;
}

unsigned int RSAPrivateKey::getFieldLength(vector<char> byteStream, int &pos){
	char curByte = byteStream[pos];
	cout<<"Length Octect#1 is "<<getBitStr(curByte)<<endl;;
	unsigned int lengthOfSeq = 0; 

	if((curByte & 0x80) == 0 )
	{
		cout<<" Data is in Short form"<<endl;
		lengthOfSeq = ( curByte & 0x7F );
	}
	else
	{
		cout<<" Data in Long Form "<<endl;
		int fieldSizeLookup = ( curByte & 0x7F );
		
		cout<<" Field Length : ";
		for(int i=0;i<fieldSizeLookup;i++)
		{
			pos++;
			curByte = byteStream[pos];
			int mask = 0x80;
			for(int i=0;i<8;i++)
				{
					lengthOfSeq<<=1;
					if((curByte&mask)!=0)
						lengthOfSeq|=0x01;
					mask>>=1;
				}			

			/*lengthOfSeq<<=8;
			lengthOfSeq|=curByte;*/
			cout<<getBitStr(curByte)<<"("<<lengthOfSeq<<")";
		}
		cout<<endl;	
	}
	pos++;
	cout<<"returning length of dataType as "<<lengthOfSeq<<" and pos is "<<pos<<endl;
	return lengthOfSeq;
}

berMpzClass RSAPrivateKey::extractBigInteger(vector<char> byteStream, int& pos, int lenOfType) {
	string bitStr = "";
	for(int i=0;i<lenOfType;i++)
		{
			bitStr+= getBitStr(byteStream[pos]);
			pos++;	
		}
	berMpzClass bigNum = berMpzClass(bitStr, 2, lenOfType);
	return bigNum;
}

/* Impl for RSAPrivateKey */

/* Construct the RSAPrivateKey info from a byte stream 
 * which is obtained by decoding base64
 */
RSAPrivateKey::RSAPrivateKey(vector<char> byteStream)
{
	cout<<"Starting to construct RSAPrivateKey"<<endl;
	/* 
	version=NULL;
	 modulus=NULL;
	 n=NULL;
	 e=NULL;
	 d=NULL;
	 p=NULL;
	 q=NULL;
	 e1=NULL; 
	 e2=NULL; 
	 otherPrimeInfos=NULL; */

/* start parsing data from byte stream */
int pos = 0;
int tag = getTag(byteStream, pos);
unsigned int lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"LenField for the sequence is "<<lengthOfSeq<<" : "<<getBitStr(lengthOfSeq)<< endl;
cout<<"We need to look at "<<lengthOfSeq<<" more bytes of "<< (byteStream.size() - pos  )<<" remaining ones "<< endl;

cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for Version with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
version = int(byteStream[pos]); pos++;
cout<<"Version is "<<version<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for modulus with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;

modulus = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"Modulus is "<<modulus.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;

n = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"n is "<<n.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;

e = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"e is "<<e.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;

d = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"d is "<<d.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;

p = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"p is "<<p.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;

q = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"q is "<<q.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
e1 = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"e1 is "<<q.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;

e2 = extractBigInteger(byteStream, pos, lengthOfSeq);
cout<<"e2 is "<<q.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
}














