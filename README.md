# SecureServerClient
A server client model using TLS and X509 certificates

# Create certificates
run the script setUpCerts.sh.

# Build
javac -d bin src/communications/\*.java

# Run
server: java -cp bin communications.MyServer 9876  
client: java -cp bin communications.MyClient localhost 9876

password: password
