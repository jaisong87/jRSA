#include<gmpxx.h>
class RSAEncrypt {
mpz_class publicKey, N;

public:
RSAEncrypt(mpz_class pkey, mpz_class num) {
	N = num;
	publicKey = pkey;
}

mpz_class encrypt(mpz_class message) {
	return bigmod(message, publicKey, N);		
}

private:

mpz_class bigmod(mpz_class b, mpz_class p, mpz_class m) {
        if(p == 1)
                return b%m;
        if(p%2 == 0)
                {
                        mpz_class tmp = bigmod(b, p/2, m);
                        return (tmp*tmp)%m;
                }
        else {
                return (b*bigmod(b, p-1, m))%m;
        }
}

};
