#Negative Test - Do not accept expired certificates
openssl req -new -days -1 -nodes -x509 -keyout private.pem -out cert1.pem 
./jrsa x509 -in cert1.pem -text
