#ifndef __DERCODEC_H__
#define __DERCODEC_H__
#include "berUtils.h"
#include<vector>
#include<string>
using namespace std;

enum DERType {INTEGER, BITSTRING, OCTETSTRING, SEQUENCE , T61STRING};

class DERCodec {
public:
static vector<char> wrapSequence(vector<char>);
static vector<char> wrapType(vector<char> byteStream, DERType tp);
static char getByte(unsigned int );
static string getBitStr(char);
static int getTag(vector<char> , int&);
static unsigned int getFieldLength(vector<char> byteStream, int &pos, int& len);
static vector<char> getPrimitiveByteStream(berMpzClass dat);
static berMpzClass extractBigInteger(vector<char> byteStream, int& pos, int lenOfType);
static vector<char> extractSequence(vector<char> byteStream, int& pos, int lenOfType);
};

#endif
