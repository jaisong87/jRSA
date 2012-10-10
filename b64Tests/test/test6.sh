# Test 1 - Opensl generate keys 
# jrsa encrypt
# openssl decrypt
./jrsa genrsa -out private.pem 1024
./jrsa rsa -in private.pem -pubout -out public.pem
openssl rsa -pubin -in public.pem -text
