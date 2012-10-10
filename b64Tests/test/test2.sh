# Test 1 - Opensl generate keys 
# jrsa encrypt
# openssl decrypt
openssl genrsa -out private.pem 1024
openssl rsa -in private.pem -pubout -out public.pem
cat file1.txt
openssl rsautl -encrypt -pubin -inkey public.pem -in file1.txt -out file1.enc
./jrsa rsautl -decrypt -inkey private.pem -in file1.enc -out file1.dec
cat file1.dec 
