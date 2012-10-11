openssl genrsa -out private.pem 1024
openssl rsa -in private.pem -pubout -out public.pem
./jrsa dgst -md5 -sign private.pem -out file1.md5 file1.txt
./jrsa dgst -md5 -verify public.pem -signature file1.md5 file1.txt
