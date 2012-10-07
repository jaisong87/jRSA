#ifndef __KEYFILE_MANAGER__
#define __KEYFILE_MANAGER__
#include "RSAPrivateKey.h"
#include "Base64Codec.h"
#include <fstream>
using namespace std;

class KeyFileManager {
public:
KeyFileManager();
RSAPrivateKey getKey(string keyFile);
int writePrivateKeyFile(string keyFile, RSAPrivateKey);
};
#endif
