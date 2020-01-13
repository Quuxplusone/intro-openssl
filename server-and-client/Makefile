CXXFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs openssl)

all: ssl-client ssl-server

keys:
	openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem
	openssl ec -in server-private-key.pem -pubout -out server-public-key.pem
	openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=server.example.com" -out server-certificate.pem
	cp server-certificate.pem server-trust-store.pem
	cp server-certificate.pem client-trust-store.pem

ssl-client: ssl-client.cc
	$(CXX) -std=c++14 $(CXXFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

ssl-server: ssl-server.cc
	$(CXX) -std=c++14 $(CXXFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

clean:
	rm -f server-certificate.pem server-private-key.pem server-public-key.pem
	rm -f client-trust-store.pem server-trust-store.pem
	rm -f ssl-client ssl-server

.PHONY: all clean
