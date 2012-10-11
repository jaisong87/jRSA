#ifndef __X509_H_
#define __X509_H_

#include "berUtils.h"
#include "DERCodec.h"
#include "RSAPublicKey.h"
#include<vector>
using namespace std;

class X509 {
	berMpzClass version;
	berMpzClass serialNum;
	berMpzClass signAlgo;
	string fromDate, toDate;
	vector<char> pubSeq;
public:
	X509(vector<char>);
	RSAPublicKey getPublicKey();
	bool isValid();
};
#endif
