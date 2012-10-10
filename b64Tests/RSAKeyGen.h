#ifndef __RSAKEYGEN_H_
#define __RSAKEYGEN_H_
#include "RSAPrivateKey.h"
#include<gmpxx.h>
#include "berUtils.h"
#include<iostream>
#include<ctime>
#include<cstdio>
#include<cstdlib>
#include<string>
#include<random>
using namespace std;

class RSAKeyGen {
private:
	int version;
	mpz_class n, e, d, p, q, e1, e2, coeff;
        //std::random_device rd; /* high entropy non-deterministic random number generator engine */
public:
	RSAKeyGen();
	RSAPrivateKey getRSAPrivateKey();	
	string eightBitStr(int N);
	bool rabinMillerTest(mpz_class num);
	mpz_class genRan(int bytes);
	mpz_class bigmodBPM(mpz_class b, mpz_class p, mpz_class m);
        mpz_class genPrime(int bits);
};

#endif
