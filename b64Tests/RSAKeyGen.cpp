#include "RSAKeyGen.h"
#include "berUtils.h"
#include<iostream>
#include<ctime>
#include<cstdio>
#include<cstdlib>
#include<string>
#include<cassert>
using namespace std;

mpz_class RSAKeyGen::bigmodBPM(mpz_class b, mpz_class p, mpz_class m) {
	if(m == 0) /* shouldn't happen - ideally an exception is to be thrown */
		return 0;
        else if( b == 0)
                return 0;
        else if(p == 0)
                return 1;
        else if( p == 1)
                return b%m;
        else if( p %2 == 0)
                {
                        mpz_class tmpVal = bigmodBPM( b, p/2, m);
                        return (tmpVal*tmpVal)%m;
                }
        else {
                        mpz_class tmpVal = bigmodBPM( b, p-1, m);
                        return (tmpVal*b)%m;
                }
}

mpz_class RSAKeyGen::genPrime(int bits) {
        for(int i=0;i<65537;i++)        
                {     
                mpz_class tmp = genRan(bits);
                if(rabinMillerTest(tmp))
                        {
			cout<<"+";
                        //cout<<"found a prme in "<<i<<" tries "<<endl;
                        return tmp;
                        }
		else cout<<".";
        }
return 0;
} 

mpz_class RSAKeyGen::genRan(int bits)
{   
  string str = "";
  std::random_device rd1; /* high entropy non-deterministic random number generator engine */

        int bytes = (bits+1)/8;;
        for(int i=0;i<bytes;i++)
                {
                        str += eightBitStr(rd1());
                }
        str = str.substr(0, bits);
        mpz_class randNum = mpz_class(str, 2);
        return randNum;
}
	RSAPrivateKey RSAKeyGen::getRSAPrivateKey() {
		RSAPrivateKey pkey = RSAPrivateKey(version, n, e, d, p, q, e1, e2, coeff, false);	
		return pkey;
	}

string RSAKeyGen::eightBitStr(int N)
{
        string bstr = "";
        int mask = 0x80;
        for(int i=0;i<8;i++, mask>>=1)
                {
                if(N&mask)
                        bstr+="1";
                else bstr += "0";
        }

        return bstr;
}

        bool RSAKeyGen::rabinMillerTest(mpz_class num) {
		if(num<2)
			return false; /* cannot use such primes */
                int lowPrimes[] = { 2, 3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
                   ,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
                   ,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
                   ,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
                   ,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
                   ,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
                   ,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
                   ,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
                   ,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
                   ,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997 };

                vector<int> primeSet(lowPrimes, lowPrimes + sizeof(lowPrimes)/sizeof(int));

                for(int i=0;i<primeSet.size();i++)
                        {
                        if(num == primeSet[i])
                                return true;
                        else if(num % primeSet[i] == 0)
                                return false;
                        }
               /* check for primality here */
                mpz_class s = (num - 1);
                mpz_class t = 0;
                while(s%2 == 0)
                        {
                                s = s/2;
                                t = t + 1;
                        }

                berMpzClass bnum = berMpzClass(s);
                int bits = bnum.getLen()-1;

                for(int k=0;k<128;k+=2)
                        {
                                //a = random number between 2 and num -1                                                
                                mpz_class a = genRan(bits);
                                mpz_class v = bigmodBPM(a, s, n); /* a pow (n-1) mod n */

                                mpz_class i = 0;
                                if( v != 1)
                                        {
                                                if ( i == (t-1))
                                                        return false;
                                                else {
                                                        i = i + 1;
                                                        v = bigmodBPM(v, 2, n);
                                                        }
                                        }
                        }
                return true;
        }

        RSAKeyGen::RSAKeyGen() {
                version = 0;
	
        p = genPrime(512); /* generate 512-bit prime */
        q = genPrime(512); /* generate 512-bit prime */

        int tries = 0;
        while(p==q && tries < 256)
                q = genPrime(512);

        n = p*q; /* modulus is pq */

        e = mpz_class("65537", 10);

        mpz_class phi = (p-1)*(q-1); /* phi = (p-1)*(q-1) */
        mpz_class e = mpz_class("65537", 10); /* e is 65537 */

        mpz_t d1;
        mpz_init(d1);
        mpz_invert (d1, e.get_mpz_t(), phi.get_mpz_t());
        d = mpz_class(d1); /* private key as multiplicative inverse of public key with modulus */
	
	assert( d != 0 );
	
        e1 = d%(p-1); /* exponent1 */
        e2 = d%(q-1); /* exponent2 */

        mpz_t d2;
        mpz_init(d2);
        mpz_invert (d2, q.get_mpz_t(), p.get_mpz_t()); /* inverse of q mod p */
        coeff = mpz_class(d2);
        }
	
