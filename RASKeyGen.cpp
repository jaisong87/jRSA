#ifndef __RSA_KEYGEN_H_
#define __RSA_KEYGEN_H_
#include<iostream>
using namespace std;

#include<gmpxx.h>

/* Generates Key Value Pairs for RSA */
class RSAKeyGen {
public:
RSAKeyGen(); /* randomly generate p, q and generate others */
RSAKeyGen(mpz_class p, mpz_class q);

mpz_class getP();
mpz_class getP();
mpz_class getN();
mpz_class getPhi();
mpz_class getPublicKey();
mpz_class getPrivateKey();

private:
};

#endif
