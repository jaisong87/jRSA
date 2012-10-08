#include "KeyFileManager.h"

KeyFileManager::KeyFileManager() {

}

RSAPrivateKey KeyFileManager::getKey(string keyFile) {
	ifstream f1(keyFile.c_str());
	string str, encodedKeyStr;
	
	while(getline(f1, str))
		{
			if(str.find("-----") == string::npos)
				{
					encodedKeyStr += str;			
				}
		}
	
	B64Codec testCodec = B64Codec();
	vector<char> bytestream = testCodec.decodeB64Stream(encodedKeyStr);
	RSAPrivateKey myKey = RSAPrivateKey(bytestream, false);
	return myKey;
}

RSAPublicKey KeyFileManager::getPublicKey(string keyFile) {
	ifstream f1(keyFile.c_str());
	string str, encodedKeyStr;
	
	while(getline(f1, str))
		{
			if(str.find("-----") == string::npos)
				{
					encodedKeyStr += str;			
				}
		}
	
	B64Codec testCodec = B64Codec();
	vector<char> bytestream = testCodec.decodeB64Stream(encodedKeyStr);
	RSAPublicKey myKey = RSAPublicKey(bytestream, false);
	return myKey;
}


