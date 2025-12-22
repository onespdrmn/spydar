# Work in Progress
The server side for this is under heavy construction.

# Setup certificate authority:
Follow instructions in README.keys

# Test the client
wget -qO- --certificate=client-test.pub      --private-key=client-test.key      --ca-certificate=rootCA.pub      "https://data.spydar.org/input?test=foo&test1=foo2"

# MariaDB Database setup
yum install mariadb1011-client-utils.x86_64 mariadb1011-server.x86_64 mariadb1011-server-utils.x86_64
sudo systemctl start mariadb
sudo systemctl enable mariadb
sudo mysql_secure_installation
go get -u github.com/go-sql-driver/mysql



