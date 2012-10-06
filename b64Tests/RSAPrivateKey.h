# ifndef __RSAPRIVATEKEY_H__ 
# define __RSAPRIVATEKEY_H__ 

#include "berUtils.h"
#include<vector>
using namespace std;

/* RSA Private Key File PKCS#1 */
class RSAPrivateKey {
int version;
berMpzClass modulus;
berMpzClass n;
berMpzClass e;
berMpzClass d;
berMpzClass p;
berMpzClass q;
berMpzClass e1; /* d mod ( p-1 ) */
berMpzClass e2; /* d mod ( q-1 ) */
berString otherPrimeInfos;

unsigned int getFieldLength(vector<char>, int&);
int getTag(vector<char>, int&);
berMpzClass extractBigInteger(vector<char> , int&, int );

public:
RSAPrivateKey(vector<char> );
};
#endif
