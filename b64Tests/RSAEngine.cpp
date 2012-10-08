#include"RSAEngine.h"
#include<algorithm>
#include<iostream>
#include<sstream>
#include<cassert>
#include<fstream>
using namespace std;

RSAEngine::RSAEngine(bool debugMode)
{
dbg = debugMode;
//do nothing..make this static or singleton later
}

vector<char> RSAEngine::encodeMessage(vector<char> message, int emLen) {
int mLen = message.size();
if(mLen > (emLen -10))
	cerr<<"RSAEngine::encodeMessage : Message length is bigger "<<endl;

char PSMsg = 0x4A;
char byte1 = 0x02;
char lastByte = 0x00;

mpz_class randVector = mpz_class("f59c5c218619fc22375fb60144cfaf09839ad4b40c32257c891f6c6cb5102ad55c97454b114b6a14920e16bffb7918480a8255fa3fdecd0f5ec98506a30c5627c3644412fd8be37e50fc393cb7144236898d2146ae35876cfefb2506e8f649310d3b5e523e12396640886d77f468595640db5a7ff1e1f9", 16);

vector<char> randomPadding = getByteStream(randVector, 119);

vector<char> encodedMessage;

	cout<<"RSAEngine::Padding with "<<(emLen -2 - mLen)<<" bytes"<<endl;
encodedMessage.push_back(byte1);
for(int i=0;i<(emLen -2 - mLen);i++)
	encodedMessage.push_back(randomPadding[i]);

encodedMessage.push_back(lastByte);

for(int i=0;i<message.size();i++)
	encodedMessage.push_back(message[i]);

	cout<<"RSAEngine::encodeMessage is returning stream with "<<encodedMessage.size()<<" bytes"<<endl;
return encodedMessage;
}

vector<char> RSAEngine::decodeMessage(vector<char> message, int emLen){
	vector<char> decodedMessage;	
	int i=0;
	
	while(message[i] != 0x00)
		i++;	

	cout<<"RSAEngine::decodeMessage Skipped the first "<<i<<" bytes and saw a "<<message[i]<<endl;
	i++;

	while(i<message.size())
		{
			decodedMessage.push_back(message[i]);
			i++;
		}
return decodedMessage;
}

mpz_class RSAEngine::bigmodBPM(mpz_class b, mpz_class p, mpz_class m) {
	if( b == 0)
		return 0;
	else if(p == 0)
		return 1;
	else if( p == 1)
		return b%m;
	else if( p %2 == 0)
		{
			mpz_class tmpVal = bigmodBPM( b, p/2, m);
			return (tmpVal*tmpVal)%m;
		}
	else {
			mpz_class tmpVal = bigmodBPM( b, p-1, m);
			return (tmpVal*b)%m;
		}
}

/* Need private Key, modulus for encryption */
vector<char> RSAEngine::encryptMessage(mpz_class privateKey, mpz_class modulus, vector<char> message) {

	cout<<" *********** start of encryption ************* "<<endl;
	vector<char> encodedMessage = encodeMessage(message, 128);
	printBytestream(encodedMessage);

	mpz_class msgNum = getBigInt(encodedMessage);
	cout<<" Message is : "<<endl<<hex<<msgNum<<endl;

	mpz_class encryptedNum = /*msgNum*/bigmodBPM(msgNum, privateKey, modulus);
	cout<<" Encrypted msgNum is : "<<endl<<hex<<encryptedNum<<endl;
	
	vector<char> encryptedMsg = getByteStream(encryptedNum, 128);
	cout<<"Encryption returned stream with "<<encryptedMsg.size()<<" bytes"<<endl;

	printBytestream(encryptedMsg);
	cout<<" *********** end of encryption ************* "<<endl;
	return encryptedMsg;
}

/* Need public key, modulus for decryption */
vector<char> RSAEngine::decryptMessage(mpz_class publicKey, mpz_class modulus, vector<char> message){
	cout<<" *********** start of decryption ************* "<<endl;
	printBytestream(message);

	mpz_class encryptedNum = getBigInt(message);
	cout<<" Message to decrypt is : "<<endl<<hex<<encryptedNum<<endl;

	mpz_class decryptedNum =  /*encryptedNum;*/bigmodBPM(encryptedNum, publicKey, modulus);
	cout<<" Decrypted num is "<<endl<<hex<<decryptedNum<<endl;

	vector<char> decryptedMsg = getByteStream(decryptedNum, 128);
	mpz_class decodedNum = getBigInt(decryptedMsg);

        vector<char> msg = decodeMessage(decryptedMsg, 128);
	cout<<"Encryption returned stream with "<<msg.size()<<" bytes"<<endl;
	cout<<" *********** end of decryption ************* "<<endl;
	return msg;
}

int RSAEngine:: getHexVal(char ch){
        int i = 0;
        if(ch >= '0' && ch<='9')
                i = ch - '0';
        else if(ch>='A'&&ch<='Z')
                i = ch - 'A' + 10;
        else
                i = ch - 'a' + 10;
        return i;
}

vector<char> RSAEngine::getByteStream(mpz_class num, int len)
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
	cout<<"RSAEngine::getByteStream is returning stream with "<<dec<<byteStream.size()<<" bytes"<<endl;
        return byteStream;
}

mpz_class RSAEngine::getBigInt(vector<char> byteStream)
{
	stringstream ss1;
        for(int i=0;i<byteStream.size();i++)
                {
			/*stringstream ss2;
			ss2<<hex<<(unsigned int)byteStream[i];
        		string str2 = ss2.str();*/
			char str2[3] = "";
			sprintf(str2, "%x", byteStream[i]&0xff);
			if(strlen(str2) == 0)
				ss1<<"00";
			else if(strlen(str2)==1)
				ss1<<"0";
			ss1<<str2;
			//assert(strlen(str2) == 2); 
	       }
	string str = ss1.str();
	cout<<" From bytestream("<<byteStream.size()<<") bytestring("<<str.length()<<") is "<<endl<<str<<endl; 
        mpz_class msgNum = mpz_class(str, 16);
	return msgNum;
}

void RSAEngine::printBytestream(vector<char> v)
{
/*cout<<" ++++++++++++++++++ ByteStream has "<<v.size()<<" bytes +++++++++++++++++"<<endl;
for(int i=0;i<v.size();i++)
        cout<<v[i];
cout<<endl;
*/}

void RSAEngine::encryptFile(string inFile, string outFile, mpz_class privateKey, mpz_class modulus)
{
vector<char> inStream;
fstream f1(inFile.c_str());
while(f1.good())
	{
		char ch;
		f1.get(ch);
		if(f1.good())
			inStream.push_back(ch);
	}
f1.close();

vector<char> outStream = encryptMessage(privateKey,modulus, inStream);

fstream f2(outFile.c_str());
for(int i=0;i<outStream.size();i++)
	{
		f2.put(outStream[i]);
	}	
f2.close();

return;
}

void RSAEngine::decryptFile(string inFile, string outFile, mpz_class publicKey, mpz_class modulus)
{
vector<char> inStream;
fstream f1(inFile.c_str());
while(f1.good())
        {
                char ch;
                f1.get(ch);
		if(f1.good())
                	inStream.push_back(ch);
        }
f1.close();

vector<char> outStream = decryptMessage(publicKey,modulus, inStream);

fstream f2(outFile.c_str());
for(int i=0;i<outStream.size();i++)
        {
                f2.put(outStream[i]);
        }
f2.close();
return;
}
