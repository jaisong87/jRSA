# ifndef __RSAPUBLICKEY_H__ 
# define __RSAPUBLICKEY_H__ 

#include "berUtils.h"
#include "Base64Codec.h"
#include "DERCodec.h"
#include<vector>
#include<fstream>
using namespace std;

/* RSA Private Key File PKCS#1 */
class RSAPublicKey {
berMpzClass n;
berMpzClass e;
bool dbg;

//unsigned int getFieldLength(vector<char>, int&);
//int getTag(vector<char>, int&);
//berMpzClass extractBigInteger(vector<char> , int&, int );
//vector<char> getPrimitiveByteStream(berMpzClass dat);

public:
RSAPublicKey(vector<char>, bool);
RSAPublicKey(berMpzClass _n, berMpzClass _e, bool);
void printKeyDetails();
vector<char> getByteStream();
int writeKeyFile(string);
string getBitStr(char);
char getByte(unsigned int);
mpz_class getPublicKey();
mpz_class getModulus();
};
#endif
