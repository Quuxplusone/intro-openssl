CXXFLAGS += $(shell pkg-config --cflags openssl)
LDFLAGS += $(shell pkg-config --libs openssl)

all: ssl-client ssl-server tls-over-tls-client tls-over-tls-server

keys:
	openssl ecparam -genkey -name prime256v1 -noout -out server-private-key.pem
	openssl ec -in server-private-key.pem -pubout -out server-public-key.pem
	openssl req -new -x509 -sha256 -key server-private-key.pem -subj "/CN=server.example.com" -out server-certificate.pem
	openssl ecparam -genkey -name prime256v1 -noout -out inner-server-private-key.pem
	openssl ec -in inner-server-private-key.pem -pubout -out inner-server-public-key.pem
	openssl req -new -x509 -sha256 -key inner-server-private-key.pem -subj "/CN=inner.example.com" -out inner-server-certificate.pem
	cp server-certificate.pem client-trust-store.pem
	cp inner-server-certificate.pem inner-client-trust-store.pem

ssl-client: ssl-client.cc
	$(CXX) -std=c++14 $(CXXFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

ssl-server: ssl-server.cc
	$(CXX) -std=c++14 $(CXXFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

tls-over-tls-client: tls-over-tls-client.cc
	$(CXX) -std=c++14 $(CXXFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

tls-over-tls-server: tls-over-tls-server.cc
	$(CXX) -std=c++14 $(CXXFLAGS) -W -Wall -Wextra $^ $(LDFLAGS) -o $@

test: keys tls-over-tls-server
	./tls-over-tls-server & \
        curl -p --proxy https://server.example.com:4433 --proxy-cacert server-certificate.pem \
            --resolve server.example.com:4433:127.0.0.1 --cacert inner-server-certificate.pem \
            https://inner.example.com
	killall tls-over-tls-server

clean:
	rm -f ssl-client client-trust-store.pem
	rm -f ssl-server server-certificate.pem server-private-key.pem server-public-key.pem
	rm -f tls-over-tls-client inner-client-trust-store.pem
	rm -f tls-over-tls-server inner-server-certificate.pem inner-server-private-key.pem inner-server-public-key.pem

.PHONY: all clean
