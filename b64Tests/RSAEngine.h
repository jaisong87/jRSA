#ifndef __RSAENGINE_H__
#define __RSAENGINE_H__
#include<iostream>
#include<string>
#include<vector>
#include<gmpxx.h>
using namespace std;


class RSAEngine {
private:
bool dbg;
vector<char> encodeMessage(vector<char> message, int emLen);
vector<char> decodeMessage(vector<char> message, int emLen);
int getHexVal(char);

public:
RSAEngine(bool);
/* Need private Key, modulus for encryption */
vector<char> encryptMessage(mpz_class privateKey, mpz_class modulus, vector<char> message);
/* Need public key, modulud for decryption */
vector<char> decryptMessage(mpz_class publicKey, mpz_class modulus, vector<char> message);
mpz_class bigmodBPM(mpz_class, mpz_class, mpz_class);
mpz_class getBigInt(vector<char> byteStream);
vector<char> getByteStream(mpz_class , int);
void printBytestream(vector<char>);
void encryptFile(string, string, mpz_class, mpz_class);
void decryptFile(string, string, mpz_class, mpz_class);
};
#endif

