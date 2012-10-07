#include "RSAEngine.h"
#include "berUtils.h"
#include "RSAPrivateKey.h"
#include "Base64Codec.h"
#include "KeyFileManager.h"
#include "RSAKeyGen.h"
#include<iostream>
using namespace std;

//openssl rsa -in key1.pem -text
void displayKeyDetails(string privateKeyFile)
{
KeyFileManager kfm = KeyFileManager();
RSAPrivateKey privateKey = kfm.getKey(privateKeyFile);
privateKey.printKeyDetails();
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

int main()
{
//displayKeyDetails("key1.pem");
RSAKeyGen k1 = RSAKeyGen();
RSAPrivateKey privateKey = k1.getRSAPrivateKey();
privateKey.printKeyDetails();

return 0;
}
