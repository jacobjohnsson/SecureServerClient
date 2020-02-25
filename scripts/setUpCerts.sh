# Sets up all certificates and keystores with password "password".

# Creates the public and private key pair for Certfification Autorithy, CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ./certs/private_CA_key.pem -out ./certs/public_CA_key.pem -days 365 < ./input/createCA.in

# Signs the root certificate, generates clienttruststore
echo 'y' | keytool -import -file ./certs/public_CA_key.pem -alias CA -keystore ./certs/clienttruststore -storepass password

# ---------- CLIENT  -----------
# Creates clientkeystore.
keytool -keystore ./certs/clientkeystore -genkey -alias CKS -storepass password < ./input/clientCert.in

# Create the request for client to get certified. Generates one file
keytool -keystore ./certs/clientkeystore -certreq -alias CKS -keyalg rsa -file ./certs/clientRequest.csr -storepass password

# Signs the request.
openssl x509 -req -CA ./certs/public_CA_key.pem -CAkey ./certs/private_CA_key.pem -in ./certs/clientRequest.csr -out ./certs/clientSigned.cer -days 365 -CAcreateserial


echo 'y' | keytool -import -keystore ./certs/clientkeystore -file ./certs/public_CA_key.pem -alias CA -storepass password


echo 'y' | keytool -import -keystore ./certs/clientkeystore -file ./certs/clientSigned.cer -alias CKS  -storepass password

# Examine client keystore.

# echo  "-------------CLIENT DONE! - CHECKING CHAIN-----------------"

# echo "password" | keytool -keystore clientkeystore -list -v

# ---------- SERVER -----------
# Creates serverkeystore.
keytool -keystore ./certs/serverkeystore -genkey -alias SKS -storepass password < ./input/serverCert.in

# Create the request for client to get certified. Generates one file
keytool -keystore ./certs/serverkeystore -certreq -alias SKS -keyalg rsa -file ./certs/serverRequest.csr -storepass password

# Signs the request.
openssl x509 -req -CA ./certs/public_CA_key.pem -CAkey ./certs/private_CA_key.pem -in ./certs/serverRequest.csr -out ./certs/serverSigned.cer -days 365 -CAcreateserial


echo 'y' | keytool -import -keystore ./certs/serverkeystore -file ./certs/public_CA_key.pem -alias CA -storepass password


echo 'y' | keytool -import -keystore ./certs/serverkeystore -file ./certs/serverSigned.cer -alias SKS  -storepass password

# Examine client keystore.

# echo  "-------------SERVER DONE! - CHECKING CHAIN-----------------"

# echo "password" | keytool -keystore serverkeystore -list -v

cp ./certs/clienttruststore ./certs/servertruststore
