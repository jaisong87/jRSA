#include "RSAPrivateKey.h"
#include<iostream>
using namespace std;
#define UNIVERSAL_PRIMITIVE_INTEGER 0x02
/* Temporary function. remove it once done */
string RSAPrivateKey::getBitStr(char N)
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

char RSAPrivateKey::getByte(unsigned int N)
{
        char ch = 0x00; 
                        int mask = 0x80;
                        for(int i=0;i<8;i++)
                                {
                                        ch<<=1;
                                        if((N&mask)!=0)
                                                ch|=0x01;
                                        mask>>=1;
                                }
return ch;
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

vector<char> RSAPrivateKey::getPrimitiveByteStream(berMpzClass dat) {
vector<char> byteStream;
char ch;
ch = UNIVERSAL_PRIMITIVE_INTEGER;
byteStream.push_back(ch);

int len = dat.getLen();
if(len<=127) {
		ch = getByte(len);
		byteStream.push_back(ch);
	}
else if(len<=65535)
	 {	/* Long Form - look at 2 more bytes*/
		ch = 0x82;
		byteStream.push_back(ch);
		ch = getByte(len>>8);
		byteStream.push_back(ch);
		ch = getByte(len);	
		byteStream.push_back(ch);
	 }
else {
		/* Long form - look at 3 more bytes(anything more is insane)*/
		ch = 0x83;
		byteStream.push_back(ch);
		ch = getByte(len>>16);
                byteStream.push_back(ch);
		ch = getByte(len>>8);
                byteStream.push_back(ch);
		ch = getByte(len);
                byteStream.push_back(ch);
	}
/* get content byte stream and append here */
vector<char> bigNumStream = dat.getByteStream();
for(int i=0;i<bigNumStream.size();i++)
	byteStream.push_back(bigNumStream[i]);

//cout<<"Returning stream of length "<<byteStream.size()<<endl;
return byteStream;
}

int RSAPrivateKey::writeKeyFile(string outFile) {
	vector<char> bstream = getByteStream();
	B64Codec cdc = B64Codec();
	string outStr = cdc.encodeB64Stream(bstream);
	string output = "-----BEGIN RSA PRIVATE KEY-----";
	
	for(int i=0;i<outStr.size();i++)
		{
			if(i%64 == 0)
				output+="\n";
			output += outStr[i];
		}
	output+="\n-----END RSA PRIVATE KEY-----\n";
	
	ofstream f1(outFile.c_str());
	f1<<output;
	f1.close();
	return 0;	
}

vector<char> RSAPrivateKey::getByteStream() {
vector<char> byteStream;
char ch;
/* Stream for version */
ch = UNIVERSAL_PRIMITIVE_INTEGER;
byteStream.push_back(ch);
ch = 0x01; /* length-1*/
byteStream.push_back(ch);
ch = 0x00; /*contents*/
byteStream.push_back(ch);

/* n, e, d, p, q, e1, e2, coeff */
vector<char> stream1 = getPrimitiveByteStream(n);
vector<char> stream2 = getPrimitiveByteStream(e);
vector<char> stream3 = getPrimitiveByteStream(d);
vector<char> stream4 = getPrimitiveByteStream(p);
vector<char> stream5 = getPrimitiveByteStream(q);
vector<char> stream6 = getPrimitiveByteStream(e1);
vector<char> stream7 = getPrimitiveByteStream(e2);
vector<char> stream8 = getPrimitiveByteStream(coeff);

for(int i=0;i<stream1.size();i++)
	byteStream.push_back(stream1[i]);

for(int i=0;i<stream2.size();i++)
	byteStream.push_back(stream2[i]);

for(int i=0;i<stream3.size();i++)
	byteStream.push_back(stream3[i]);

for(int i=0;i<stream4.size();i++)
	byteStream.push_back(stream4[i]);

for(int i=0;i<stream5.size();i++)
	byteStream.push_back(stream5[i]);

for(int i=0;i<stream6.size();i++)
	byteStream.push_back(stream6[i]);

for(int i=0;i<stream7.size();i++)
	byteStream.push_back(stream7[i]);

for(int i=0;i<stream8.size();i++)
	byteStream.push_back(stream8[i]);

//cout<<"Making sequence of length "<<dec<<byteStream.size()<<" bytes"<<endl;

unsigned int bLen = byteStream.size();
ch = 0x30; /* Universal non primitive ( SEQUENCE ) */ 

vector<char> finalStream;
finalStream.push_back(ch);

if(bLen<=127) {
                ch = getByte(bLen);
                finalStream.push_back(ch);
        }
else if(bLen<=65535)
         {      /* Long Form - look at 2 more bytes*/
                ch = 0x82;
                finalStream.push_back(ch);
                ch = getByte(bLen>>8);
                finalStream.push_back(ch);
                ch = getByte(bLen);
                finalStream.push_back(ch);
         }
else {
                /* Long form - look at 3 more bytes(anything more is insane)*/
                ch = 0x83;
                finalStream.push_back(ch);
                ch = getByte(bLen>>16);
                finalStream.push_back(ch);
                ch = getByte(bLen>>8);
                finalStream.push_back(ch);
                ch = getByte(bLen);
                finalStream.push_back(ch);
        }

for(int i=0;i<byteStream.size();i++)
	finalStream.push_back(byteStream[i]);

//cout<<"Returning byte stream of "<<finalStream.size()<<" bytes"<<endl;
return finalStream;
}

RSAPublicKey RSAPrivateKey::getPublicKey() {
RSAPublicKey pubKey = RSAPublicKey(n, e, false);
return pubKey;
}

mpz_class RSAPrivateKey::getPrivateKey() {
	return d.getData();
}

mpz_class RSAPrivateKey::getModulus()
{
	return n.getData();
}
