#ifndef __Base64Codec_H_
#define __Base64Codec_H_

#include<iostream>
#include<string>
#include<vector>
using namespace std;

class B64Codec { 

private:
vector<char> stringToByteStream(string);
string getBitString(char ch);

public:
B64Codec();
vector<char> decodeB64Stream(string);

};


#endif

