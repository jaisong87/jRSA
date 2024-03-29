#include "RSAEngine.h"
#include "berUtils.h"
#include "RSAPrivateKey.h"
#include "Base64Codec.h"
#include "KeyFileManager.h"
#include "RSAKeyGen.h"
#include "RSASignature.h"
#include<iostream>
using namespace std;

//rsautl -encrypt -in hello.txt -out hello.enc -inkey private.pem
void encDecData(string keyFile, string inFile, string outFile , bool doEncrypt) {
	if(doEncrypt == true) 	{ /* Encrypt with private Key */
	//	cout<<"Reading Key from "<<keyFile<<" and encrypting "<<inFile<<" to "<<outFile<<endl;
		RSAEngine eng = RSAEngine(false);
		KeyFileManager kfm = KeyFileManager();
		RSAPublicKey publicKey = kfm.getPublicKey(keyFile);
		eng.encryptFile(inFile, outFile, publicKey.getPublicKey() , publicKey.getModulus());
	}
	else { /* Decrypt with public Key */
	//	cout<<"Reading Key from "<<keyFile<<" and encrypting "<<inFile<<" to "<<outFile<<endl;
		RSAEngine eng = RSAEngine(false);
		KeyFileManager kfm = KeyFileManager();
		RSAPrivateKey privateKey = kfm.getKey(keyFile);
		eng.decryptFile(inFile, outFile, privateKey.getPrivateKey() , privateKey.getModulus());	
	}
return;	
}

void hexDump(string inFile)
{
	vector<char> keyStream;

        ifstream f1(inFile.c_str());
        while(f1.good())
        {
                char ch;
                f1.get(ch);
                if(f1.good())
                        keyStream.push_back(ch);
        }
        f1.close();
	
	int pos = 0;
	int len = keyStream.size();
	cout<<DERCodec::extractBigInteger(keyStream, pos, len).getRsaHexStr()<<endl;
	return;
}

void parseX509(string certFile, string pubFile){
	cout<<"Parsing X509 Certificate"<<endl;
	KeyFileManager kfm = KeyFileManager();
	X509 cert = kfm.getCert(certFile);

	if(cert.isValid())
		{
	cout<<"Writing Key to "<<pubFile<<endl;	
	RSAPublicKey pubKey = cert.getPublicKey();
	pubKey.writeKeyFile(pubFile);
		}
	else {
		cout<<"Certificate is invalid( expired certificate )"<<endl;
		}
}

void rsaDgst( string plainFile, string dgstFile, string keyFile, bool doSign, bool doVerify) {
	if(plainFile == "")
		cerr<<"ERROR! - Please specify an input file"<<endl;
	else if(dgstFile == "")
		cerr<<"ERROR! - Please specify a digest file"<<endl;
	else if(keyFile == "")
		cerr<<"ERROR! - Please specify a key file"<<endl;
	else if((doSign^doVerify) == false)
		cerr<<"ERROR! - Incorrect sign/verify option"<<endl;
	else if(doVerify)
		{
			//cout<<"Verifying the signature : "<<dgstFile<<" using public key : "<<keyFile<<" against : "<<plainFile<<endl;
			RSASignature inpSignature = RSASignature(dgstFile, keyFile, plainFile,true);
		}
	else {
			//cout<<"Verifying the signature : "<<dgstFile<<" using public key : "<<keyFile<<" against : "<<plainFile<<endl;
			RSASignature inpSignature = RSASignature(dgstFile, keyFile, plainFile,false);
		}
}

//openssl rsa -in key1.pem -text
void displayKeyDetails(string privateKeyFile, bool isPublic)
{
KeyFileManager kfm = KeyFileManager();

if(isPublic == false)
	{
	RSAPrivateKey privateKey = kfm.getKey(privateKeyFile);
	privateKey.printKeyDetails();
	}
else{
	RSAPublicKey pubKey = kfm.getPublicKey(privateKeyFile);
	pubKey.printKeyDetails();
	}
return;
}

void createPublicKeyFile(string keyFile, bool isPublic, string outFile)
{
	KeyFileManager kfm = KeyFileManager();
	if(isPublic)
		{
			RSAPublicKey pubKey = kfm.getPublicKey(keyFile);
			pubKey.writeKeyFile(outFile);
		}
	else {
		RSAPrivateKey priKey = kfm.getKey(keyFile);
		RSAPublicKey pubKey = priKey.getPublicKey();
		pubKey.writeKeyFile(outFile);
	}
return;
}

/* This serves as a unit test */
void createPrivateKeyFile(string keyFile, string outFile)
{
        KeyFileManager kfm = KeyFileManager();
        RSAPrivateKey priKey = kfm.getKey(keyFile);
        priKey.writeKeyFile(outFile);
return;
}


void testBerMpzClass() {
string num;
while(cin>>num)
        {
                berMpzClass n1 = berMpzClass(num, 16);
                cout<<n1.getLen()<<" --> "<<n1.getRsaHexStr()<<endl;
        }
return;
}

//openssl genrsa -out private.pem 1024
void genPemFile(string outFile) {
RSAKeyGen k1 = RSAKeyGen();
RSAPrivateKey privateKey = k1.getRSAPrivateKey();
privateKey.writeKeyFile(outFile);
return;
}

void testBase64Codec() {
	string str;
	B64Codec cdc = B64Codec();
	while(getline(cin, str))
		{
			vector<char> v;
			for(int i=0;i<str.length();i++)
				v.push_back(str[i]);

			string b64 = cdc.encodeB64Stream(v);
			cout<<"b64 : "<<b64<<endl;

			vector<char> v1 = cdc.decodeB64Stream(b64);			
			string str2 = "";
			for(int i=0;i<v1.size();i++)
				str2 += v1[i];
			cout<<str2<<endl;
		}
}

int main(int argc, char* argv[])
{
string util = string(argv[1]);
//displayKeyDetails("key1.pem");
//genPemFile("test.pem");
//testBase64Codec();

	int pos = 2;
	if(util =="genrsa")
		{
			//cout<<"doing Genrsa"<<endl;		
			string outFile = "key.pem";
			while(pos<argc)
				{
					string nextArg = string(argv[pos]); pos++;
					if(nextArg == "-out")
						{
					outFile = string(argv[pos]); pos++;	
						}	
				}
			genPemFile(outFile);
		}
	else if(util == "rsa")
		{
			//openssl rsa -in key1.pem -text
			//cout<<"Doing rsa "<<endl;
			bool displayKey = false;
			bool isPublic = false;
			bool createPub = false;
			bool createPri = false;
			bool pubOut = false;
			string keyFile = "";
			string outFile = "";
			while(pos<argc)
                                {
					 string nextArg = string(argv[pos]); pos++;
					 if(nextArg == "-text") {
						displayKey = true;
					}
					else if(nextArg == "-in") {
						keyFile = string(argv[pos]); pos++;		
					}
					else if(nextArg == "-pubin")
						isPublic = true;
					else if(nextArg == "-out")
						{
						createPri = true;
						outFile = string(argv[pos]); pos++;		
						}
					else if(nextArg == "-pubout")
						{
						pubOut = true;			
						}
				}
			if( (isPublic && createPri ) || pubOut )
				{		
				createPri = false;
				createPub = true;
				}

			if(keyFile=="")
				{
					cout<<"ERROR!! - Please specify a key File"<<endl;
				}	
			else {
				if(createPub == true || createPri == true )
					{
					if(outFile == "")
						cout<<"ERROR!! - Please specify an output File (-out)"<<endl;
					else if(createPub)
						createPublicKeyFile(keyFile, isPublic, outFile);
					else if(createPri)	
						createPrivateKeyFile(keyFile,  outFile);
					}
				else {
					displayKeyDetails(keyFile, isPublic);
					}
				}
		}
	else if(util == "rsautl")
		{
			//cout<<"Doing rsautl "<<endl;
                        string keyFile = "";
                        string outFile = "";
			string inFile = "";
			bool doEncrypt = false;
			bool doDecrypt = false;
			//rsautl -encrypt -in hello.txt -out hello.enc -inkey private.pem
			while(pos<argc) {
					 string nextArg = string(argv[pos]); pos++;
                                         if(nextArg == "-inkey") {
                                                keyFile = string(argv[pos]); pos++;
                                        }
                                        else if(nextArg == "-in") {
                                                inFile = string(argv[pos]); pos++;
                                        }
                                        else if(nextArg == "-out") {
                                                outFile = string(argv[pos]); pos++;
						}
                                        else if(nextArg == "-encrypt")
                                                {
                                                doEncrypt = true;
                                                }
                                        else if(nextArg == "-decrypt")
                                                {
                                                doDecrypt = true;
                                                }
					}	
			if(doEncrypt^doDecrypt) {
				if(keyFile == "")
					cout<<"ERROR!! - KeyFile not specified"<<endl;
				else if(inFile == "")
					cout<<"ERROR!! - inFile not specified"<<endl;
				else if(outFile == "")
					cout<<"ERROR!! - outFile not specified"<<endl;
				else 
					encDecData(keyFile, inFile, outFile , doEncrypt);	
			}
			else cout<<"Error!! - Invalid Encrypt/decrypt option!!!"<<endl;		
		}
	else if(util == "dgst")
		{
			string plainFile;
			string dgstFile;
			string keyFile;
			bool doSign = false;
			bool doVerify = false;
			 while(pos<argc) {
                                         string nextArg = string(argv[pos]); pos++;
                                         if(nextArg == "-sign") {
						doSign = true;
                                                keyFile = string(argv[pos]); pos++;
                                        	}	
					else if(nextArg == "-verify") { 
						doVerify = true;
                                                keyFile = string(argv[pos]); pos++;
						}
					else if(nextArg == "-signature" || nextArg == "-out" ) {
                                                dgstFile = string(argv[pos]); pos++;
						}
					else {
						plainFile = nextArg;
						}
					}
			rsaDgst(plainFile, dgstFile, keyFile, doSign, doVerify);
		}
	else if(util == "x509")
		{
			string certFile = "";
			bool dispCert = false;
			string pubFile = "";
                         while(pos<argc) {
                                         string nextArg = string(argv[pos]); pos++;
                                         if(nextArg == "-text") {
                                                dispCert = true;
                                                }
					 else if(nextArg == "-in") {
                                                certFile = string(argv[pos]); pos++;
                                                }
					 else if(nextArg == "-pubout") {
                                                pubFile = string(argv[pos]); pos++;
                                                }
					}
			parseX509(certFile, pubFile);
		}
	else if(util == "hexdump")
		{
			string inFile = "";
			 while(pos<argc) {
                                         string nextArg = string(argv[pos]); pos++;
					 inFile = nextArg;
					}
			hexDump(inFile);
		}
	else {
		cerr<<"Unknown utility"<<endl;
		}

return 0;
}
