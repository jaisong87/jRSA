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

/* Constructor with all args */
RSAPrivateKey::RSAPrivateKey(int _version, berMpzClass _n, berMpzClass _e, berMpzClass _d, berMpzClass _p, berMpzClass _q, berMpzClass _e1, berMpzClass _e2, berMpzClass _coeff, bool _dbg) {
	version = _version;
	n = _n;
	e = _e;
	d = _d;
	p = _p;
	q = _q;
	e1 = _e1;
	e2 = _e2;
	coeff = _coeff;
	dbg = _dbg;
}

/* Get the Tag */
int RSAPrivateKey::getTag(vector<char> byteStream, int &pos){

	char curByte = byteStream[pos];
	if(dbg) cout<<getBitStr(curByte)<<" : "<<int(curByte)<<endl;
	
if((curByte&(1<<7)) || (curByte&(1<<6)));
else
        if(dbg) cout<<" Universal "<<endl;

	int tag = curByte&(0x1F);
	pos++;
	if(dbg) cout<<"Tag number is "<<tag<<" and pos is "<<pos<<endl;
	return tag;
}

unsigned int RSAPrivateKey::getFieldLength(vector<char> byteStream, int &pos){
	char curByte = byteStream[pos];
	if(dbg) cout<<"Length Octect#1 is "<<getBitStr(curByte)<<endl;;
	unsigned int lengthOfSeq = 0; 

	if((curByte & 0x80) == 0 )
	{
		if(dbg) cout<<" Data is in Short form"<<endl;
		lengthOfSeq = ( curByte & 0x7F );
	}
	else
	{
		if(dbg) cout<<" Data in Long Form "<<endl;
		int fieldSizeLookup = ( curByte & 0x7F );
		
		if(dbg) cout<<" Field Length : ";
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
			if(dbg) cout<<getBitStr(curByte)<<"("<<lengthOfSeq<<")";
		}
		if(dbg) cout<<endl;	
	}
	pos++;
	if(dbg) cout<<"returning length of dataType as "<<lengthOfSeq<<" and pos is "<<pos<<endl;
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
RSAPrivateKey::RSAPrivateKey(vector<char> byteStream, bool debugFlag)
{
	dbg = debugFlag;
	if(dbg) 
		cout<<"Starting to construct RSAPrivateKey"<<endl;

/* start parsing data from byte stream */
int pos = 0;
int tag = getTag(byteStream, pos);
unsigned int lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"LenField for the sequence is "<<lengthOfSeq<<" : "<<getBitStr(lengthOfSeq)<< endl;
cout<<"We need to look at "<<lengthOfSeq<<" more bytes of "<< (byteStream.size() - pos  )<<" remaining ones "<< endl;
cout<<"------------------------------"<<endl;
       }

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for Version with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

version = int(byteStream[pos]); pos++;

if(dbg) { 
cout<<"Version is "<<version<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

/*
tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for modulus with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

modulus = extractBigInteger(byteStream, pos, lengthOfSeq);
if(dbg) { 
cout<<"Modulus is "<<modulus.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}
*/

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

n = extractBigInteger(byteStream, pos, lengthOfSeq);

if(dbg) { 
cout<<"n is "<<n.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

e = extractBigInteger(byteStream, pos, lengthOfSeq);
if(dbg) { 
cout<<"e is "<<e.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

d = extractBigInteger(byteStream, pos, lengthOfSeq);

if(dbg) { 
cout<<"d is "<<d.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

p = extractBigInteger(byteStream, pos, lengthOfSeq);

if(dbg) { 
cout<<"p is "<<p.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

q = extractBigInteger(byteStream, pos, lengthOfSeq);

if(dbg) { 
cout<<"q is "<<q.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

e1 = extractBigInteger(byteStream, pos, lengthOfSeq);

if(dbg) { 
cout<<"e1 is "<<q.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

e2 = extractBigInteger(byteStream, pos, lengthOfSeq);

if(dbg) { 
cout<<"e2 is "<<q.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
	}

tag =  getTag(byteStream, pos);
lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) {
cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for n with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
        }

coeff = extractBigInteger(byteStream, pos, lengthOfSeq);

if(dbg) {
cout<<"e2 is "<<q.getData()<<" and pos is "<<pos<<endl;
cout<<"------------------------------"<<endl;
        }

return;
}

void RSAPrivateKey::printKeyDetails()
{
cout<<"modulus:"<<endl;
cout<<hex<<n.getRsaHexStr()<<endl;
cout<<"publicExponent: "<<dec<<e.getData()<<" ("<<hex<<e.getData()<<")"<<endl;
cout<<"privateExponent:"<<endl;
cout<<hex<<d.getRsaHexStr()<<endl;
cout<<"prime1:"<<endl;
cout<<hex<<p.getRsaHexStr()<<endl;
cout<<"prime2:"<<endl;
cout<<hex<<q.getRsaHexStr()<<endl;
cout<<"exponent1:"<<endl;
cout<<hex<<e1.getRsaHexStr()<<endl;
cout<<"exponent2:"<<endl;
cout<<hex<<e2.getRsaHexStr()<<endl;
cout<<"coefficient:"<<endl;
cout<<hex<<coeff.getRsaHexStr()<<endl;
}
