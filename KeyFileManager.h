#ifndef __KEYFILE_MANAGER__
#define __KEYFILE_MANAGER__
#include "RSAPrivateKey.h"
#include "Base64Codec.h"
#include "X509.h"
#include <fstream>
using namespace std;

class KeyFileManager {
public:
KeyFileManager();
RSAPrivateKey getKey(string keyFile);
RSAPublicKey getPublicKey(string keyFile); 
X509 getCert(string certFile);
};
#endif
