all:
	g++ -g jrsa.cpp RSAEngine.h RSAEngine.cpp Base64Codec.h Base64Codec.cpp RSAPrivateKey.h RSAPrivateKey.cpp KeyFileManager.h KeyFileManager.cpp berUtils.h berUtils.cpp RSAKeyGen.h RSAKeyGen.cpp RSAPublicKey.h RSAPublicKey.cpp DERCodec.h DERCodec.cpp -lgmp -lgmpxx -std=c++0x -o jrsa
clean:
	rm jrsa
