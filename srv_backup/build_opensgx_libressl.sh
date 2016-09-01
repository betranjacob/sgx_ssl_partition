cp -r build/libressl-2.4.1/ssl/* build/opensgx/libsgx/libressl/ssl/
cp -r build/libressl-2.4.1/include/openssl/* build/opensgx/libsgx/libressl/include/openssl/
#cp -r build/libressl-2.4.1/* build/opensgx/libsgx/libressl

cd build/opensgx/
cd libsgx
make clean
cd ../user
make clean
cd ../
cd qemu
./configure-arch
make -j 4
cd ../
make -C libsgx
cd ../../
./build-ssl-partition.sh --ns
cd build/opensgx/
make -C user
