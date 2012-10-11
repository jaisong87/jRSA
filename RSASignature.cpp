#include "RSASignature.h"
#include "DERCodec.h"
#include "RSAEngine.h"
#include<fstream>
using namespace std;

RSASignature::RSASignature(string dgstFile, string keyFile, string plainFile, bool readSign)
{
	if(readSign)
		{
		readSignature(dgstFile,keyFile);	
		verifySignature(plainFile);
		}
	else 
		createSignature(plainFile,keyFile, dgstFile);	
}

void RSASignature::readSignature(string dgstFile, string keyFile)
	{
	vector<char> keyStream;

	ifstream f1(dgstFile.c_str());
	while(f1.good())
        {
                char ch;
                f1.get(ch);
                if(f1.good())
                        keyStream.push_back(ch);
        }
	f1.close();
	
	KeyFileManager kfm = KeyFileManager();
	RSAPublicKey publicKey = kfm.getPublicKey(keyFile);
	
	int pos1 = 0;
	int len1 = keyStream.size();
	berMpzClass tmp = DERCodec::extractBigInteger(keyStream, pos1, len1);		

	//cout<<"Dumping signature :"<<endl; 
	//cout<<tmp.getRsaHexStr()<<endl;	
	
	RSAEngine eng = RSAEngine(false);
	vector<char> decStream = eng.decryptMessage(publicKey.getPublicKey(), publicKey.getModulus(), keyStream);
	
	/*pos1  = 0;
	len1 = decStream.size();
	cout<<"Decrypted Stream :"<<endl;
	cout<<DERCodec::extractBigInteger(decStream, pos1, len1).getRsaHexStr()<<endl;
	*/
	int pos = 0;
	int len = 0;
	
	
	/* Sequence<Sequence, OctetString> */
	int tag = DERCodec::getTag(decStream, pos);
	unsigned int lengthOfSeq = DERCodec::getFieldLength(decStream, pos, len);
	
	/* MD5 Signature = "06082a864886f70d02050500" */
	tag = DERCodec::getTag(decStream, pos);
        lengthOfSeq = DERCodec::getFieldLength(decStream, pos, len);
	signHeader = DERCodec::extractBigInteger(decStream, pos, lengthOfSeq);
	//cout<<"sign header : "<<signHeader.getRsaHexStr()<<endl;	
	
	tag = DERCodec::getTag(decStream, pos);
        lengthOfSeq = DERCodec::getFieldLength(decStream, pos, len);
	signDigest = DERCodec::extractBigInteger(decStream, pos, lengthOfSeq);
	//cout<<"sign digest : "<<signDigest.getRsaHexStr()<<endl;
}

bool RSASignature::verifySignature(string plainFile)
{
	berMpzClass dgst = getDigest(plainFile);
	if(dgst.getData() == signDigest.getData())
		{
		cout<<"VERIFIED OK"<<endl;
		return true;
		}
	else {
		cout<<"VERIFY FAILED"<<endl;
		return false;
	}
}	

void RSASignature::createSignature(string plainFile, string keyFile, string outFile)
{
	signDigest = getDigest(plainFile);
	signHeader = berMpzClass("06082a864886f70d02050500", 16);	
	
	vector<char> stream1 = DERCodec::wrapType(signHeader.getByteStream(), SEQUENCE);
	vector<char> stream2 = DERCodec::wrapType(signDigest.getByteStream(), OCTETSTRING);
	
	vector<char> finalStream;
	for(int i=0;i<stream1.size();i++)
		finalStream.push_back(stream1[i]);
	
	for(int i=0;i<stream2.size();i++)
		finalStream.push_back(stream2[i]);
	
	vector<char> signature = DERCodec::wrapType(finalStream, SEQUENCE);
	KeyFileManager kfm = KeyFileManager();
	RSAPrivateKey privateKey = kfm.getKey(keyFile);
	
	RSAEngine eng = RSAEngine(false);
	vector<char> encStream = eng.encryptMessage(privateKey.getPrivateKey(),privateKey.getModulus(), signature);
	
	ofstream f2(outFile.c_str());
	for(int i=0;i<encStream.size();i++)
        {
                f2.put(encStream[i]);
        }
	f2.close();
}

berMpzClass RSASignature::getDigest(string plainFile)
{
	vector<char> keyStream;

        ifstream f1(plainFile.c_str());
        while(f1.good())
        {
                char ch;
                f1.get(ch);
                if(f1.good())
                        keyStream.push_back(ch);
        }
        f1.close();
	
	char* data = new char[keyStream.size()];
	for(int i=0;i<keyStream.size();i++)
		data[i] = keyStream[i];	
	
	unsigned char result[MD5_DIGEST_LENGTH+2];
	memset(result, 0, MD5_DIGEST_LENGTH+2);
	MD5((unsigned char*) data, keyStream.size(), result);
		
	vector<char> md5Digest;
	for(int i=0;i<MD5_DIGEST_LENGTH;i++)
		md5Digest.push_back(result[i]);

	int pos = 0;
	int len = MD5_DIGEST_LENGTH;
	berMpzClass dgst = DERCodec::extractBigInteger(md5Digest, pos, len);
        //cout<<"sign digest : "<<signDigest.getRsaHexStr()<<endl;	
	return dgst;
}
