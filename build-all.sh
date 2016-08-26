#!/usr/bin/env bash

#export LIBRESSL_SGX_FLAGS="--enable-sgx"
export LIBRESSL_SGX_FLAGS="--enable-sgx --enable-sgx-keyblock"

#export BUSYWAIT_SGX_FAGS=""
export BUSYWAIT_SGX_FAGS="-DOPENSSL_WITH_SGX_KEYBLOCK"

# this is so that we dont have to wait to input password
sudo ls

# clean up and copy libressl to right folders
rm -rf build/opensgx/libsgx/libressl
mkdir build/opensgx/libsgx/libressl  # dont think this is needed 
rm -rf build/busywait/libressl
mkdir build/busywait/libressl        # dont think this is needed
cd build/libressl-2.4.1/
make clean
cd ../../
cp -r build/libressl-2.4.1/* build/opensgx/libsgx/libressl/
cp -r build/libressl-2.4.1/* build/busywait/libressl/
cd build/opensgx/libsgx
make clean
cd ../
cd user
make clean
cd ../

# build opensgx
cd qemu
./configure-arch
make -j 4
cd ../
make -C libsgx
cd ../../

export LIBRESSL_SGX_PATH=$(pwd)/build/opensgx/libsgx/libressl
export MUSL_LIBC_PATH=$(pwd)/build/opensgx/libsgx/musl-libc

cd $LIBRESSL_SGX_PATH
aclocal
automake
autoconf
./configure CFLAGS="-nostdlib -DHAVE_TIMEGM -DHAVE_STRSEP -DSGX_ENCLAVE -I$MUSL_LIBC_PATH/include" LIBS="$MUSL_LIBC_PATH/lib/libc.so" --host="x86_64-linux" $LIBRESSL_SGX_FLAGS --enable-shared=no && make -j 4
cd ../../../..

cd build/opensgx/
make -C user
cd ../../

# build libressl
export STATICLIBSSL=$(pwd)/build/libressl-2.4.1
cd build/libressl-2.4.1/
./configure LDFLAGS="-lrt" $LIBRESSL_SGX_FLAGS --enable-shared --prefix=${STATICLIBSSL}/.openssl
make install-strip -j 4
cd ../../

# build nginx
cd build/nginx-1.11.1
touch $(pwd)/build/libressl-2.4.1/.openssl/include/openssl/ssl.h
./configure --with-openssl=$STATICLIBSSL --with-cc-opt="-O0 -g -DOPENSSL_WITH_SGX" --with-openssl-opt="${LIBRESSL_SGX_FLAGS} --prefix=${STATICLIBSSL}/.openssl" --with-http_ssl_module --with-http_v2_module --with-debug
sudo make install -j 4
cd ../../

# build busywait
cd build/busywait/libressl
./configure LDFLAGS="-lrt -lpthread" CFLAGS="-O0 -g -DSGX_ENCLAVE" $LIBRESSL_SGX_FLAGS --host="x86_64-linux"
make -j 4
cd ..
make clean
cp ../opensgx/user/test/openssl/libressl-pipe.c ./
cp ../opensgx/user/test/openssl/libressl-pipe.h ./
make CFLAGS=$BUSYWAIT_SGX_FLAGS
cd ../..
