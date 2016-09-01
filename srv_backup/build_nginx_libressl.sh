export STATICLIBSSL=$(pwd)/build/libressl-2.4.1

cd build/libressl-2.4.1/
./configure LDFLAGS="-lrt" --enable-sgx --enable-shared --prefix=${STATICLIBSSL}/.openssl
make install-strip -j 4
cd ../..
cd build/nginx-1.11.1
touch /home/bagon/workspace/gz99/ssl-partition/build/libressl-2.4.1/.openssl/include/openssl/ssl.h
./configure --with-openssl=$STATICLIBSSL --with-cc-opt="-O0 -g -DOPENSSL_WITH_SGX" --with-openssl-opt="--enable-sgx --prefix=${STATICLIBSSL}/.openssl" --with-http_ssl_module --with-http_v2_module --with-debug 
sudo make install -j 4
cd ../../
