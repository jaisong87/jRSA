#ifndef __BERUTILS_H__
#define __BERUTILS_H__
#include "gmpxx.h"
#include<iostream>
#include<string>
using namespace std;

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

class berMpzClass {
mpz_class data;
int len;

public:
	berMpzClass() {
		data = 0;
		len = 0;
	}

	berMpzClass(string num, int base, int l)
		{
			len = l;
			cout<<"Constructing mpz_class from "<<num<<" base-"<<base<<endl;
			data = mpz_class(num,base);
		}

mpz_class getData() {
		return data;
	}

int getLen() {
		return len;
	}
};


#endif
