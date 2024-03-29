# ifndef __RSAPRIVATEKEY_H__ 
# define __RSAPRIVATEKEY_H__ 

#include "berUtils.h"
#include "Base64Codec.h"
#include "RSAPublicKey.h"
#include "DERCodec.h"
#include<vector>
#include<fstream>
using namespace std;

/* RSA Private Key File PKCS#1 */
class RSAPrivateKey {
int version;
berMpzClass n;
berMpzClass e;
berMpzClass d;
berMpzClass p;
berMpzClass q;
berMpzClass e1; /* d mod ( p-1 ) */
berMpzClass e2; /* d mod ( q-1 ) */
berMpzClass coeff;
bool dbg;

//unsigned int getFieldLength(vector<char>, int&, int&);
//int getTag(vector<char>, int&);
//berMpzClass extractBigInteger(vector<char> , int&, int );
//vector<char> getPrimitiveByteStream(berMpzClass dat);

public:
RSAPrivateKey(vector<char>, bool);
RSAPrivateKey(int _version, berMpzClass _n, berMpzClass _e, berMpzClass _d, berMpzClass _p, berMpzClass _q, berMpzClass _e1, berMpzClass _e2, berMpzClass _coeff, bool _dbg);
void printKeyDetails();
vector<char> getByteStream();
int writeKeyFile(string);
RSAPublicKey getPublicKey();
//string getBitStr(char);
//char getByte(unsigned int);
mpz_class getPrivateKey();
mpz_class getModulus();
};
#endif
