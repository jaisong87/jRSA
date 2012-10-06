#include "berUtils.h"
#include "RSAPrivateKey.h"
#include "Base64Codec.h"
#include<iostream>
using namespace std;

int main()
{

/*
berString b1 = berString("abcd", 10);

cout<<b1.getData()<<endl;
cout<<b1.getLen()<<endl;

berMpzClass bigNum = berMpzClass("12345678910111213141516171819202122", 10, 35);

mpz_class tmp = bigNum.getData();
int len = bigNum.getLen();

cout<<tmp<<"  : "<<len<< " <-> "<<bigNum.getData()<<" : "<< bigNum.getLen()<<endl;
tmp*=10;
cout<<tmp<<"  : "<<len<< " <-> "<<bigNum.getData()<<" : "<< bigNum.getLen()<<endl;
 */

string inp = string("MIICXAIBAAKBgQDNL8HdXOazYFh3Smk+bp6j4UmuXcH5DRVIKCkAXCDnJtpmTfxT") +
string("/nP/x1Dx/JO5Z/BGamdavUsdbVTy6q6Wd58lrfPvlRSnpZkhV7NUigp/gMrSWn1D") +
string("9r13/8A8GhBNcc5ZQNEVRIcjw/G0HTfYZeczJwqly9H6azYe65Qv7CWi+QIDAQAB") +
string("AoGAVD6zfkvSfPul1vS6WWPZxreNJQZhyfvRLRswGnG5IK8XJMIIRARJZE9VsMVf") +
string("cdR3FrJBVUQ7Pw3QvxwUKrtan8WG1gLoNQ415Y/wrz4DPvgskQG2hRyE4Drq8dS5") +
string("rbK0oSyJ7wQjKFO89b4nIm04SZXgTCb+YjxG6xZtNDsUarECQQDtXH1PDrynReYd") +
string("ulqwszKCh9K66eT/cL7Tgj2/OEHVKr6BpkXij57DvyMqBA9w1H0z4uku26GuBvsu") +
string("SdRmVkl/AkEA3Ux7MzPZ9aiN3aDY1EGGC0f4+uAj6bHn8fLnGyS+DQh9sv94ED2m") +
string("zf1tL6oOZ8juq44Cy12xpk0/ZJ4+rIGfhwJAcV6Jo2cAiEyEepJ1mowcheflqMzq") +
string("SW9KVa+RWnG+T9hYoYgPPQUn6Yqzeu/xiAyVuGCay3yvnnVLJ3Kv9ikkdQJAAiyy") +
string("OTqVNbjGTBs8hjlum8XFSJHTSISbBuGgK8AcrfwbYBrqjx5L+VI4NHOzWIm87qqi") +
string("lGUDTeMMcGytqPxNGQJBAKwSRHZfwt0JCiPjT9zMqH6Tpj05Y2s6e7BMBf9Wfatr") +
string("0ou3RF7H+a9w5UTx6UES66L9jGvZXk44Zs6z1UVII3M="); /* input base64 string */

B64Codec testCodec = B64Codec();

vector<char> bytestream = testCodec.decodeB64Stream(inp);
cout<<" Size of Byte stream is "<<bytestream.size()<<endl;


RSAPrivateKey myKey = RSAPrivateKey(bytestream);

return 0;
}
