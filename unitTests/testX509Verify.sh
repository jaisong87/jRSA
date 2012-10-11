#openssl create certificate and sign files
#jrsa will read public key from certificate and verify dgst 
openssl req -new -days 730 -nodes -x509 -keyout private.pem -out cert1.pem 
openssl rsa -in private.pem -pubout -out public.pem
openssl dgst -md5 -sign private.pem -out file1.md5 file1.txt

./jrsa x509 -in cert1.pem -text -pubout pub.pem
./jrsa dgst -md5 -verify public.pem -signature file1.md5 file1.txt
