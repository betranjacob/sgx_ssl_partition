all: libressl-pipe

libressl-pipe: libressl-pipe.c busywait.c
	gcc $(CFLAGS) -Wall -o libressl-pipe libressl-pipe.c busywait.c -Wl,--wrap,read,--wrap,write -I./libressl/include/ -I./include/ -L./libressl/ssl/.libs/ -L./libressl/crypto/.libs/ -static -lssl -lcrypto -lpthread

nowait: libressl-pipe.c
	gcc $(CFLAGS) -Wall -o libressl-pipe libressl-pipe.c -I./libressl/include/ -I./include/ -L./libressl/ssl/.libs/ -L./libressl/crypto/.libs/ -static -lssl -lcrypto -lpthread CFLAGS

clean:
	rm libressl-pipe

