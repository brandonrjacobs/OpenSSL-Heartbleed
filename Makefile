
all:	libssl libcrypto ssl_client ssl_heartbeat ssl_server ssl_server_fixed

clean:
	rm -f ssl_client ssl_heartbeat ssl_server ssl_server_fixed
	rm -f ssl_client.o ssl_heartbeat.o ssl_server.o
	rm -f libssl.a libcrypto.a

ssl:	
	rm -f libssl.a
	if [ ! -d openssl ] && [ -d openssl-1.0.1 ];\
	then\
		ln -s openssl-1.0.1 openssl;\
	fi

	cd openssl; make -n clean; make

	if [ ! -e libssl.a ];\
	then\
		ln -s openssl/libssl.a libssl.a;\
	fi
	

libssl: openssl

libcrypto: openssl

openssl: libssl.a libcrypto.a

libssl.a:
	if [ ! -d openssl ] && [ -d openssl-1.0.1 ];\
	then\
		ln -s openssl-1.0.1 openssl;\
	fi

	cd openssl; make -n clean; make

	if [ ! -e libssl.a ];\
	then\
		ln -s openssl/libssl.a libssl.a;\
	fi

libcrypto.a:
	if [ ! -d openssl ] && [ -d openssl-1.0.1 ];\
	then\
		ln -s openssl-1.0.1 openssl;\
	fi

	cd openssl; make -n clean; make

	if [ ! -e libcrypto.a ];\
	then\
		ln -s openssl/libcrypto.a libcrypto.a;\
	fi

ssl_client: ssl_client.c
	cc -g -o ssl_client ssl_client.c -Lopenssl -lssl -lcrypto

ssl_heartbeat: ssl_heartbeat.c
	cc -g -o ssl_heartbeat ssl_heartbeat.c -Lopenssl -lssl -lcrypto

ssl_server: ssl_server.c
	cc -g -o ssl_server ssl_server.c -Lopenssl -lssl -lcrypto

ssl_server_fixed: ssl_server.c
	cc -g -o ssl_server_fixed ssl_server.c -Lopenssl -lssl -lcrypto

