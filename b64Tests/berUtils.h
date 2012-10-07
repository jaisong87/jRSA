#ifndef __BERUTILS_H__
#define __BERUTILS_H__
#include "gmpxx.h"
#include<iostream>
#include<sstream>
#include<string>
using namespace std;

/*
class berString{
string data;
int len;

public:
berString() {
data = "";
len = 0;
}

berString(string dat, int l)
	{
		data = dat;
		len = l;	
	}

string getData() {
                return data;
        }

int getLen() {
                return len;
        }

};
*/

class berMpzClass {
mpz_class data;
int len;

public:
berMpzClass();
berMpzClass(mpz_class);
berMpzClass(string num, int base);
berMpzClass(string num, int base, int l);

mpz_class getData();
int getLen();
string getRsaHexStr();
};

#endif
