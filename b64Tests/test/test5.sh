# Test 1 - Opensl generate keys 
# jrsa encrypt
# openssl decrypt
openssl genrsa -out private.pem 1024
openssl rsa -in private.pem -pubout -out public.pem
./jrsa rsa -pubin -in public.pem -text
