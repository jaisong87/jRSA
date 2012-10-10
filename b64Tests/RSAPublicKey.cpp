#include "RSAPublicKey.h"
#include<iostream>
using namespace std;

/* Impl for RSAPublicKey*/

/* Constructor with all args */
RSAPublicKey::RSAPublicKey( berMpzClass _n, berMpzClass _e, bool _dbg) {
	n = _n;
	e = _e;
	dbg = _dbg;
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

/* start parsing data from byte stream */
int pos = 0;
int len = 0;
int z = byteStream.size();
	//berMpzClass num = DERCodec::extractBigInteger(byteStream, pos, z);
	//cout<<"CP0 : "<<num.getRsaHexStr()<<endl;
pos = 0;

int tag = DERCodec::getTag(byteStream, pos);
unsigned int lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);

/* This is a sequence in case of both PKCS#1 and PKCS#8  */
/*int pos1 = 0;
string tmp = DERCodec::extractBigInteger(byteStream, pos1, 4).getRsaHexStr();
cout<<tmp<<endl;

int posY = pos;
tmp = DERCodec::extractBigInteger(byteStream, posY, 4).getRsaHexStr();
cout<<tmp<<endl;
*/

/*in case of PKCS#1 this is n */
tag =  DERCodec::getTag(byteStream, pos);
lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
n = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq); /* algoIDF for PKCS#8*/
//cout<<dec<<" Tag for algoIdf is "<<tag<<" Pos : "<<pos<<endl;
//lengthOfSeq = 15;
//cout<<"AlgoIdentifier SEQ("<<lengthOfSeq<<":"<<pos<<") is : "<<hex<<n.getData()<<endl;

if(tag == 2) /*PKCS#1 */
{

	tag =  DERCodec::getTag(byteStream, pos);
	lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
	e = DERCodec::extractBigInteger(byteStream, pos, lengthOfSeq);
}
else {	/* PKCS-8*/
	/* Get tag as a 61Bitstring*/
	tag =  DERCodec::getTag(byteStream, pos);
	lengthOfSeq = DERCodec::getFieldLength(byteStream, pos, len);
	vector<char> pcks1Seq = extractSequence(byteStream, pos, lengthOfSeq);		

	/* Now you have a sequence that has <int, int> */
	int pos1 = 1;
	tag =  DERCodec::getTag(pcks1Seq , pos1);
	lengthOfSeq = DERCodec::getFieldLength(pcks1Seq , pos1, len);
	
	/* Extract n*/
	tag =  DERCodec::getTag(pcks1Seq , pos1);
	lengthOfSeq = DERCodec::getFieldLength(pcks1Seq , pos1, len);
	n = DERCodec::extractBigInteger(pcks1Seq, pos1, lengthOfSeq);
	
	/*Extract e*/	
	tag =  DERCodec::getTag(pcks1Seq , pos1);
	lengthOfSeq = DERCodec::getFieldLength(pcks1Seq , pos1, len);	
	e = DERCodec::extractBigInteger(pcks1Seq, pos1, lengthOfSeq);
}

return;
}

void RSAPublicKey::printKeyDetails()
{
cout<<"publicExponent: "<<dec<<e.getData()<<" ("<<hex<<e.getData()<<")"<<endl;
cout<<"modulus:"<<endl;
cout<<hex<<n.getRsaHexStr()<<endl;
}

int RSAPublicKey::writeKeyFile(string outFile) {
	vector<char> bstream = getByteStream();
	B64Codec cdc = B64Codec();
	string outStr = cdc.encodeB64Stream(bstream);
	string output = "-----BEGIN PUBLIC KEY-----";
	
	for(int i=0;i<outStr.size();i++)
		{
			if(i%64 == 0)
				output+="\n";
			output += outStr[i];
		}
	output+="\n-----END PUBLIC KEY-----\n";
	
	ofstream f1(outFile.c_str());
	f1<<output;
	f1.close();
	return 0;	
}

vector<char> RSAPublicKey::getByteStream() {
vector<char> byteStream;

/* n, e, d, p, q, e1, e2, coeff */
vector<char> stream1 = DERCodec::getPrimitiveByteStream(n);
vector<char> stream2 = DERCodec::getPrimitiveByteStream(e);

for(int i=0;i<stream1.size();i++)
	byteStream.push_back(stream1[i]);

for(int i=0;i<stream2.size();i++)
	byteStream.push_back(stream2[i]);

	vector<char> publicKeyStream = DERCodec::wrapSequence(byteStream);

bool usePkcs8 = true;
if(usePkcs8 == false)
	{
	return publicKeyStream;
	}
else {
berMpzClass algoIdf =  berMpzClass("300d06092a864886f70d0101010500", 16);
vector<char> algoIdfStream = algoIdf.getByteStream(); 
vector<char> pubStream = DERCodec::wrapType(byteStream, SEQUENCE);

/* Add a zero also*/
vector<char> pubStream2;
char ch = 0x00;
pubStream2.push_back(ch);
for(int i=0;i<pubStream.size();i++)
	pubStream2.push_back(pubStream[i]);

/*int l = pubStream2.size();
int tpos = 0;
berMpzClass num = DERCodec::extractBigInteger(pubStream2, tpos, l);
cout<<hex<<"CP1 : "<<num.getRsaHexStr()<<endl;*/

vector<char> bitStringStrm = DERCodec::wrapType(pubStream2, BITSTRING);

vector<char> seq;
for(int i=0;i<algoIdfStream.size();i++)
	seq.push_back(algoIdfStream[i]);
for(int i=0;i<bitStringStrm.size();i++)
	seq.push_back(bitStringStrm[i]);

vector<char> finalStream = DERCodec::wrapSequence(seq);
int z = finalStream.size();
int ppos = 0;
	//berMpzClass num1 = DERCodec::extractBigInteger(finalStream, ppos, z);
	//cout<<"CP0 : "<<num1.getRsaHexStr()<<endl;
return finalStream;
	}
}

mpz_class RSAPublicKey::getPublicKey() {
        return e.getData();
}

mpz_class RSAPublicKey::getModulus()
{
        return n.getData();
}
