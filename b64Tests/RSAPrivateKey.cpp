#include "RSAPrivateKey.h"
#include<iostream>
using namespace std;
/* Impl for RSAPrivateKey */

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


/* Construct the RSAPrivateKey info from a byte stream 
 * which is obtained by decoding base64
 */
RSAPrivateKey::RSAPrivateKey(vector<char> byteStream, bool debugFlag)
{
/* hex dump for debug purposes */
/*
int pos1 = 0;
int len1 = byteStream.size();
string hexdump = DERCodec::extractBigInteger(byteStream, pos1, len1).getRsaHexStr();
cout<<hexdump<<endl;
*/

/* start parsing data from byte stream */
int pos = 0;
int len = 0;
int tag = DERCodec::getTag(byteStream, pos);
unsigned int lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);

/* Manually extract version */
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
version = int(byteStream[pos]); 
pos++;

/*Extract n*/
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
n = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

/* Extract e*/
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
e = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

/* Extract d*/
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
d = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

/*Extract p*/
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
p = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

/*Extract q*/
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
q = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

/*Extract e1*/
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
e1 = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

/* Extract e2*/
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
e2 = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

/* Extract coeff */
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
coeff = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);

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
ch = 0x02;//UNIVERSAL_PRIMITIVE_INTEGER;
byteStream.push_back(ch);
ch = 0x01; /* length-1*/
byteStream.push_back(ch);
ch = 0x00; /*contents*/
byteStream.push_back(ch);

/* n, e, d, p, q, e1, e2, coeff */
vector<char> stream1 = DERCodec::getPrimitiveByteStream(n);
vector<char> stream2 = DERCodec::getPrimitiveByteStream(e);
vector<char> stream3 = DERCodec::getPrimitiveByteStream(d);
vector<char> stream4 = DERCodec::getPrimitiveByteStream(p);
vector<char> stream5 = DERCodec::getPrimitiveByteStream(q);
vector<char> stream6 = DERCodec::getPrimitiveByteStream(e1);
vector<char> stream7 = DERCodec::getPrimitiveByteStream(e2);
vector<char> stream8 = DERCodec::getPrimitiveByteStream(coeff);

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

//byteStream.push_back(char(0x00)); /* last field is NULL type*/
/* Wrap this as a DER Sequence */
vector<char> byteStreamSeq = DERCodec::wrapSequence(byteStream);

return byteStreamSeq;
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
