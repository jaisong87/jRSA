#include "RSAPublicKey.h"
#include<iostream>
using namespace std;
#define UNIVERSAL_PRIMITIVE_INTEGER 0x02

/* Temporary function. remove it once done */
string RSAPublicKey::getBitStr(char N)
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

char RSAPublicKey::getByte(unsigned int N)
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
RSAPublicKey::RSAPublicKey( berMpzClass _n, berMpzClass _e, bool _dbg) {
	n = _n;
	e = _e;
	dbg = _dbg;
}

/* Get the Tag */
int RSAPublicKey::getTag(vector<char> byteStream, int &pos){

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

unsigned int RSAPublicKey::getFieldLength(vector<char> byteStream, int &pos){
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

berMpzClass RSAPublicKey::extractBigInteger(vector<char> byteStream, int& pos, int lenOfType) {
	string bitStr = "";
	for(int i=0;i<lenOfType;i++)
		{
			bitStr+= getBitStr(byteStream[pos]);
			pos++;	
		}
	berMpzClass bigNum = berMpzClass(bitStr, 2, lenOfType);
	return bigNum;
}

vector<char> extractSequence(vector<char> byteStream, int& pos, int lenOfType) {
	vector<char> subSeq;
	for(int i=0;i<lenOfType;i++)
                {
			subSeq.push_back(byteStream[pos]);
			pos++;
		}
	return subSeq;
}

/* Impl for RSAPublicKey */

/* Construct the RSAPublicKey info from a byte stream 
 * which is obtained by decoding base64
 */
RSAPublicKey::RSAPublicKey(vector<char> byteStream, bool debugFlag)
{
	dbg = debugFlag;
	if(dbg) 
		cout<<"Starting to construct RSAPublicKey"<<endl;

/* start parsing data from byte stream */
int pos = 0;
int tag = getTag(byteStream, pos);
unsigned int lengthOfSeq = getFieldLength(byteStream, pos);

if(dbg) { 
cout<<"LenField for the sequence is "<<lengthOfSeq<<" : "<<getBitStr(lengthOfSeq)<< endl;
cout<<"We need to look at "<<lengthOfSeq<<" more bytes of "<< (byteStream.size() - pos  )<<" remaining ones "<< endl;
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

if(tag == 2)
{
	if(dbg) { 
		cout<<"n is "<<n.getData()<<" and pos is "<<pos<<endl;
		cout<<"------------------------------"<<endl;
	}

	tag =  getTag(byteStream, pos);
	lengthOfSeq = getFieldLength(byteStream, pos);

	if(dbg) { 
		cout<<"We need to look at "<<lengthOfSeq<<"("<<getBitStr(lengthOfSeq)<<") more bytes for e with Tag:"<< tag <<" and "<<(byteStream.size() - pos  )<<" remaining ones "<< endl;
	}

	e = extractBigInteger(byteStream, pos, lengthOfSeq);
	if(dbg) { 
		cout<<"e is "<<e.getData()<<" and pos is "<<pos<<endl;
		cout<<"------------------------------"<<endl;
	}
}
else {	/* PKCS-8*/
	tag =  getTag(byteStream, pos);
	lengthOfSeq = getFieldLength(byteStream, pos);
	vector<char> pcks1Seq = extractSequence(byteStream, pos, lengthOfSeq);	
	
	/* Now you have a sequence that has <int, int> */
	int pos1 = 1;
	tag =  getTag(pcks1Seq , pos1);
	lengthOfSeq = getFieldLength(pcks1Seq , pos1);
	cout<<" Need to look at "<<lengthOfSeq<<" bytes out of "<<pcks1Seq.size()-pos1<<" bytes for pubKey and tag is"<<tag<<endl;	
	
	tag =  getTag(pcks1Seq , pos1);
	lengthOfSeq = getFieldLength(pcks1Seq , pos1);
	cout<<" Need to look at "<<lengthOfSeq<<" bytes out of "<<pcks1Seq.size()-pos1<<" bytes for pubKey and tag is"<<tag<<endl;	
	 	
	n = extractBigInteger(pcks1Seq, pos1, lengthOfSeq);
		
	tag =  getTag(pcks1Seq , pos1);
	lengthOfSeq = getFieldLength(pcks1Seq , pos1);
	cout<<" Need to look at "<<lengthOfSeq<<" bytes out of "<<pcks1Seq.size()-pos1<<" bytes for pubKey and tag is"<<tag<<endl;	
	
	e = extractBigInteger(pcks1Seq, pos1, lengthOfSeq);
}

return;
}

void RSAPublicKey::printKeyDetails()
{
cout<<"publicExponent: "<<dec<<e.getData()<<" ("<<hex<<e.getData()<<")"<<endl;
cout<<"modulus:"<<endl;
cout<<hex<<n.getRsaHexStr()<<endl;
}

vector<char> RSAPublicKey::getPrimitiveByteStream(berMpzClass dat) {
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

int RSAPublicKey::writeKeyFile(string outFile) {
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
	output+="\n-----END RSA PUBLIC KEY-----\n";
	
	ofstream f1(outFile.c_str());
	f1<<output;
	f1.close();
	return 0;	
}

vector<char> RSAPublicKey::getByteStream() {
vector<char> byteStream;

/* n, e, d, p, q, e1, e2, coeff */
vector<char> stream1 = getPrimitiveByteStream(n);
vector<char> stream2 = getPrimitiveByteStream(e);

for(int i=0;i<stream1.size();i++)
	byteStream.push_back(stream1[i]);

for(int i=0;i<stream2.size();i++)
	byteStream.push_back(stream2[i]);

unsigned int bLen = byteStream.size();
char ch = 0x30; /* Universal non primitive ( SEQUENCE ) */ 

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

mpz_class RSAPublicKey::getPublicKey() {
        return e.getData();
}

mpz_class RSAPublicKey::getModulus()
{
        return n.getData();
}
