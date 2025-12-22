# Work in Progress
The server side for this is under heavy construction.

# Setup certificate authority:
    1. The Root CA is the "master" key used to sign all other requests.
            Step A: Generate the Root Key:
                openssl genrsa -out rootCA.key 4096
            Step B: Generate the Root Certificate: 
                openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.pub

    2. Generate the Server Certificate
        This certificate is used by a server (like a web server) to prove its identity to clients.

            Step A: Create the Server Private Key:
            openssl genrsa -out server.key 2048

            Step B: Create a Certificate Signing Request (CSR) 
            openssl req -new -key server.key -out server.csr

            Step C: Sign the CSR with your Root CA 
            openssl x509 -req -in server.csr -CA rootCA.pub -CAkey rootCA.key -CAcreateserial -out server.pub -days 825 -sha256

    3. Generate the Client Certificate
        This is used for Mutual TLS (mTLS) where the server needs to verify the identity of the user/client.

            Step A: Create the Client Private Key 
                openssl genrsa -out client.key 2048

            Step B: Create the Client CSR 
                openssl req -new -key client.key -out client.csr

            Step C: Sign the CSR with your Root CA 
                openssl x509 -req -in client.csr -CA rootCA.pub -CAkey rootCA.key -CAcreateserial -out client.pub -days 825 -sha256

    4. Secure the private keys
            chmod 600 keys/*.key


# Test the client
 wget -qO- --certificate=client-test.pub      --private-key=client-test.key      --ca-certificate=rootCA.pub      "https://data.spydar.org/input?test=foo&test1=foo2"


# Database setup
yum install mariadb1011-client-utils.x86_64 mariadb1011-server.x86_64 mariadb1011-server-utils.x86_64
sudo systemctl start mariadb
sudo systemctl enable mariadb
sudo mysql_secure_installation
go get -u github.com/go-sql-driver/mysql



# Install go compiler version 1.24 or higher:
	https://golang.org/dl/

# Install redis
	sudo yum install redis

# Handy redis commands:
	redis-cli
	flushall	#clear everything from the redis cache
	smembers ids    #display all the keys in redis
	smembers s.<id> #display a specific key in redis found from 'smembers ids'
	hget h.<id> time #display time seen in Unix seconds from the epoch for a specific id
	hget h.<id> last #display last seen


