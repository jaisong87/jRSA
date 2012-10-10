# Test 1 - Opensl generate keys 
# jrsa encrypt
# openssl decrypt
./jrsa genrsa -out private.pem 1024
openssl rsa -in private.pem -text
