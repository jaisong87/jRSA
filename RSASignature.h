#ifndef __RSA_SIGNATURE_H__
#define __RSA_SIGNATURE_H__
#include "berUtils.h"
#include "KeyFileManager.h"
#include "RSAPrivateKey.h"
#include "RSAPublicKey.h"
#include <openssl/md5.h>

class RSASignature {
	
	berMpzClass signHeader;
	berMpzClass signDigest;
	void readSignature(string dgstFile, string keyFile);
	void createSignature(string inputFile, string keyFile, string dgstFile);
public:
	RSASignature(string signFile, string keyFile,  string plainFile,bool readSignature);
	bool verifySignature(string);
	berMpzClass getDigest(string plainFile);

};

#endif
