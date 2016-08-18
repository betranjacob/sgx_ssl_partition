LIBRESSL_TEST_PATH=./libressl

libressl-pipe: libressl-pipe.c
	gcc -Wall -o libressl-pipe libressl-pipe.c -I./libressl/include/ -I./include/ -L./libressl/.openssl/lib/ -static -lssl -lcrypto -lpthread

