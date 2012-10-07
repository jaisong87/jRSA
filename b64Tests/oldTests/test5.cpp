#include<iostream>
#include "RSAEngine.h"
#include<gmpxx.h>
using namespace std;

void printBytestream(vector<char> v)
{
cout<<" ------------- ByteStream has "<<v.size()<<" bytes ----------------"<<endl;
for(int i=0;i<v.size();i++)
	cout<<v[i];
cout<<endl;
}

mpz_class bigmodBPM(mpz_class b, mpz_class p, mpz_class m) {
        if( p == 1)
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


int main()
{


RSAEngine eng1  = RSAEngine(true); 

mpz_class b = 10;
mpz_class p = 10;
mpz_class m = 10;


mpz_class modulus = mpz_class("151606966700507383757283474220447546510425650252999733015302474751042326569822975406396333207967568012082350005460976486383905246142723048476578402776815356454435753826396767939237284260304637609291774758277787595366501887794354494727208259558648550627233557493112447131365459046927459025186543287113044454363", 10);
mpz_class publicKey = mpz_class("65537", 10);
mpz_class privateKey = mpz_class("96670636914224072811283993838568785893833674083687166684109359863455876604457517421577068959942577470084216921406361999931290970460323992138604679396986982950973300579532234779110964316508062989247480080655119520642287549759141315334822611232550083054128285209890595608432439039792013684741066820972881154169", 10);

eng1.encryptFile("file1.txt", "file1.ssl", privateKey, modulus);
eng1.decryptFile("file1.ssl", "file1_dec.txt", publicKey, modulus);

cout<<"Private Key : "<<endl<<hex<<privateKey<<endl;
cout<<"Public Key : "<<endl<<hex<<publicKey<<endl;
cout<<"Modulus : "<<endl<<hex<<modulus<<endl;


/*
string str;// = "hello";

cout<<"Enter a message : ";
while(getline(cin, str)) {

vector<char> message;
for(int i=0;i<str.length();i++)
	message.push_back(str[i]);
printBytestream(message);

vector<char> m1 = eng1.encryptMessage(privateKey, modulus, message);
printBytestream(m1);

vector<char> m2 = eng1.decryptMessage(publicKey, modulus, m1);
printBytestream(m2);

cout<<"Enter a message : ";
	}
*/

/*
mpz_class m = 110;
cout<<m<<endl;
mpz_class m1 = eng1.bigmodBPM(m, privateKey, modulus);
cout<<m1<<endl;
mpz_class m2 = eng1.bigmodBPM(m1, publicKey, modulus);
cout<<m2<<endl;
*/
return 0;
}
