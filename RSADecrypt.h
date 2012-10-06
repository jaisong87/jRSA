#include<gmpxx.h>
class RSADecrypt {
mpz_class privateKey, N;

public:
RSADecrypt(mpz_class pkey, mpz_class num) {
	N = num;
	privateKey = pkey;
}

mpz_class decrypt(mpz_class message) {
	return bigmod(message, privateKey, N);		
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
