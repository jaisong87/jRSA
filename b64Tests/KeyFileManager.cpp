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
	
	cout<<"encoded key string is : "<<encodedKeyStr<<endl;	

	B64Codec testCodec = B64Codec();
	vector<char> bytestream = testCodec.decodeB64Stream(encodedKeyStr);
	RSAPrivateKey myKey = RSAPrivateKey(bytestream, false);
	return myKey;
}

int KeyFileManager::writePrivateKeyFile(string keyFile, RSAPrivateKey){
return 0;
}

