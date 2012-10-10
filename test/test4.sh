# Test 1 - Opensl generate keys 
# jrsa encrypt
# openssl decrypt
openssl genrsa -out private.pem 1024
./jrsa rsa -in private.pem -text
