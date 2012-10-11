all:
	g++ -g jrsa.cpp RSAEngine.h RSAEngine.cpp Base64Codec.h Base64Codec.cpp X509.h X509.cpp RSAPrivateKey.h RSAPrivateKey.cpp KeyFileManager.h KeyFileManager.cpp berUtils.h berUtils.cpp RSAKeyGen.h RSAKeyGen.cpp RSAPublicKey.h RSAPublicKey.cpp DERCodec.h DERCodec.cpp RSASignature.h RSASignature.cpp -lgmp -lgmpxx -std=c++0x -lssl -lcrypto -o jrsa
clean:
	rm jrsa
