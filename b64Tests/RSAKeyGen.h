#ifndef __RSAKEYGEN_H_
#define __RSAKEYGEN_H_
#include "RSAPrivateKey.h"

class RSAKeyGen {
private:
	int version;
	mpz_class n, e, d, p, q, e1, e2, coeff;
public:
	RSAKeyGen();
	RSAPrivateKey getRSAPrivateKey();	
};

#endif
