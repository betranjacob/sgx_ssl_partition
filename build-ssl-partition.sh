#!/usr/bin/env bash

# adopted from https://gist.github.com/Belphemur/3c022598919e6a1788fc
# includes neverbleed patch

# proc for building faster
NB_PROC=$(grep -c ^processor /proc/cpuinfo)
 
# set the log folder
NGINX_LOG_DIR=/var/log/nginx

# names of latest versions of each package
export NGINX_VERSION=1.11.1
export VERSION_LIBRESSL=libressl-2.4.1
export VERSION_NGINX=nginx-$NGINX_VERSION
 
# URLs to the source directories
export SOURCE_LIBRESSL=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/
export SOURCE_NGINX=http://nginx.org/download/
export SOURCE_OPENSGX=https://github.com/sslab-gatech/opensgx.git

# set where LibreSSL and nginx will be built
export BPATH=$(pwd)/build
export STATICLIBSSL=$BPATH/$VERSION_LIBRESSL
export LIBSSL_TEST=$BPATH/busywait/libressl

# TODO: 
print_usage() {
  cat <<EOF
[usage] $0 [option]
-h|--help      : print help 
-d|--download  : downloads the sources
-n|--nginx     : build nginx-libressl and libressl for opensgx
--ns           : build libressl for opensgx
-g|--git       : build after cloning from git
-c|--clean     : remove the build folder
EOF
  # for f in test/*.c; do
  #   printf " %-30s: %s\n" "$f" "$(cat $f| head -1 | sed 's#//##g')"
  # done
}

# TODO: make it acurate
print_finish() {
    echo "All done.";
	echo "This build has not edited your existing /etc/nginx directory.";
	echo "If things aren't working now you may need to refer to the";
	echo "configuration files the new nginx ships with as defaults,";
	echo "which are available at /etc/nginx-default";
}

build_libressl() {
	# build static LibreSSL
	echo "Configure & Build LibreSSL"
	
	# cd $BPATH/$VERSION_LIBRESSL
	cd $STATICLIBSSL
	# ./configure LDFLAGS=-lrt --prefix=${STATICLIBSSL}/.openssl/ && make install-strip -j $NB_PROC

	echo $(pwd)

	#no strip for callgrind
	./configure LDFLAGS="-lrt" CFLAGS="-O0 -g" --enable-sgx --enable-shared --prefix=${STATICLIBSSL}/.openssl/ && make install -j $NB_PROC
}

build_stock_libressl() {
	# build static LibreSSL
	echo "Configure & Build Stock LibreSSL"
	
	# cd $BPATH/$VERSION_LIBRESSL
	cd $STATICLIBSSL
	# ./configure LDFLAGS=-lrt --prefix=${STATICLIBSSL}/.openssl/ && make install-strip -j $NB_PROC

	echo $(pwd)

	#no strip for callgrind
	./configure LDFLAGS="-lrt" CFLAGS="-O0 -g" --enable-shared --prefix=${STATICLIBSSL}/.openssl/ && make install -j $NB_PROC
}

build_nginx() {
	# build nginx, with various modules included/excluded
	echo "Configure & Build Nginx"
	cd $BPATH/$VERSION_NGINX

	mkdir -p $BPATH/nginx
	./configure  --with-openssl=$STATICLIBSSL \
        --with-openssl-opt='--enable-sgx --prefix=${STATICLIBSSL}/.openssl' \
	--with-debug \
	--with-ld-opt="-lrt"  \
	--with-cc-opt='-O0 -g -DOPENSSL_WITH_SGX' \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=$NGINX_LOG_DIR/error.log \
	--http-log-path=$NGINX_LOG_DIR/access.log \
	--with-http_ssl_module \
	--with-http_v2_module \
	--with-file-aio \
	--with-ipv6 \
	--with-http_gzip_static_module \
	--with-http_stub_status_module \
	--without-mail_pop3_module \
	--without-mail_smtp_module \
	--without-mail_imap_module \
	--with-http_image_filter_module \
	--lock-path=/var/lock/nginx.lock \
	--pid-path=/var/run/nginx.pid \
	--http-client-body-temp-path=/var/lib/nginx/body \
	--http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
	--http-proxy-temp-path=/var/lib/nginx/proxy \
	--http-scgi-temp-path=/var/lib/nginx/scgi \
	--http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
	--with-http_stub_status_module \
	--with-http_realip_module \
	--with-http_auth_request_module \
	--with-http_addition_module \
	--with-http_geoip_module \
	--with-http_gzip_static_module

	touch $STATICLIBSSL/.openssl/include/openssl/ssl.h
	# make -j $NB_PROC && sudo checkinstall --pkgname="nginx-libressl" --pkgversion="$NGINX_VERSION" \
	# --provides="nginx" --requires="libc6, zlib1g" --strip=yes \
	# --stripso=yes --backup=yes -y --install=yes

	# dont strip for callgrind
	make -j $NB_PROC && sudo checkinstall --pkgname="nginx-libressl" --pkgversion="$NGINX_VERSION" \
	--provides="nginx" --requires="libc6, zlib1g" --strip=no \
	--stripso=no --backup=yes -y --install=yes
}

build_stock_nginx() {
	# build nginx, with various modules included/excluded
	echo "Configure & Build stock Nginx"
	cd $BPATH/$VERSION_NGINX

	mkdir -p $BPATH/nginx
	./configure  --with-openssl=$STATICLIBSSL \
        --with-openssl-opt='--prefix=${STATICLIBSSL}/.openssl' \
	--with-debug \
	--with-ld-opt="-lrt"  \
	--with-cc-opt='-O0 -g' \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=$NGINX_LOG_DIR/error.log \
	--http-log-path=$NGINX_LOG_DIR/access.log \
	--with-http_ssl_module \
	--with-http_v2_module \
	--with-file-aio \
	--with-ipv6 \
	--with-http_gzip_static_module \
	--with-http_stub_status_module \
	--without-mail_pop3_module \
	--without-mail_smtp_module \
	--without-mail_imap_module \
	--with-http_image_filter_module \
	--lock-path=/var/lock/nginx.lock \
	--pid-path=/var/run/nginx.pid \
	--http-client-body-temp-path=/var/lib/nginx/body \
	--http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
	--http-proxy-temp-path=/var/lib/nginx/proxy \
	--http-scgi-temp-path=/var/lib/nginx/scgi \
	--http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
	--with-http_stub_status_module \
	--with-http_realip_module \
	--with-http_auth_request_module \
	--with-http_addition_module \
	--with-http_geoip_module \
	--with-http_gzip_static_module

	touch $STATICLIBSSL/.openssl/include/openssl/ssl.h
	# make -j $NB_PROC && sudo checkinstall --pkgname="nginx-libressl" --pkgversion="$NGINX_VERSION" \
	# --provides="nginx" --requires="libc6, zlib1g" --strip=yes \
	# --stripso=yes --backup=yes -y --install=yes

	# dont strip for callgrind
	make -j $NB_PROC && sudo checkinstall --pkgname="nginx-libressl" --pkgversion="$NGINX_VERSION" \
	--provides="nginx" --requires="libc6, zlib1g" --strip=no \
	--stripso=no --backup=yes -y --install=yes
}

build_opensgx() {
	echo "Configure & Build OpenSGX"
	cd $BPATH/opensgx
	# compile opensgx
	# Compile QEMU
	cd qemu
	./configure-arch
	make -j $NB_PROC

	# Back to opensgx/
	cd ..

	# Compile sgx library and user-level code
	make -C libsgx
	# make -C user

	# create new key
	./opensgx -k

	# back to build, prob not necessary
	cd ../
}

build_libressl_sgx() {
	echo "Configure & Build LibreSSL for OpenSGX"

	LIBRESSL_SGX_PATH=$BPATH/opensgx/libsgx/libressl
	MUSL_LIBC_PATH=$BPATH/opensgx/libsgx/musl-libc

	cd $LIBRESSL_SGX_PATH
	aclocal
        automake
	autoconf
	./configure CFLAGS="-nostdlib -DHAVE_TIMEGM -DHAVE_STRSEP -DSGX_ENCLAVE -I$MUSL_LIBC_PATH/include" LIBS="$MUSL_LIBC_PATH/lib/libc.so" --host="x86_64-linux" --enable-sgx --enable-shared=no && make -j $NB_PROC

	cd $BPATH
	cd ..
}

build_libressl_busywait() {
	echo "Configure & Build LibreSSL for busywait"
	
	if [ ! -d "$LIBSSL_TEST" ]; then
		cp -r libressl-2.4.1/ $LIBSSL_TEST/
		
		cd $LIBSSL_TEST
		make clean

		aclocal
	    automake
		autoconf

		cd $BPATH
		cd ..
	fi

	echo "Copying changed libressl files"
	RSYNC_OPTIONS="--include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs"
	rsync -avP --include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs $STATICLIBSSL/crypto/ $LIBSSL_TEST/crypto/
	rsync -avP --include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs $STATICLIBSSL/ssl/ $LIBSSL_TEST/ssl/
	rsync -avP --include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs $STATICLIBSSL/include/openssl/ $LIBSSL_TEST/include/openssl/

	cd $LIBSSL_TEST
	./configure LDFLAGS="-lrt -lpthread" CFLAGS="-O0 -g -DSGX_ENCLAVE" --enable-sgx --enable-shared --host="x86_64-linux" && make -j $NB_PROC

	cd $BPATH/busywait

	rm -f libressl-pipe
	
	cp ../opensgx/user/test/openssl/libressl-pipe.c ./
	cp ../opensgx/user/test/openssl/libressl-pipe.h ./

	make
	
	cd $BPATH
	cd ..
}

download_sources() {
	# grab the source files
	echo "Download sources"
	# TODO: make sure we include downloaded sources we used in the repo
	wget -P ./build $SOURCE_LIBRESSL$VERSION_LIBRESSL.tar.gz
	wget -P ./build $SOURCE_NGINX$VERSION_NGINX.tar.gz
	git clone $SOURCE_OPENSGX ./build/opensgx
	 
	# expand the source files
	echo "Extract Packages"
	cd build
	tar xzf $VERSION_NGINX.tar.gz
	tar xzf $VERSION_LIBRESSL.tar.gz
	cd ../
}

install_dependencies() {
	# ensure that we have the required software to compile our own nginx
	sudo apt-get -y install curl wget build-essential libgd-dev libgeoip-dev checkinstall git

	# the default options also require
	# - HTTP gzip module requires the zlib library
	# - HTTP image filter module requires the GD library
	# - GeoIP module requires the GeoIP library
	sudo apt-get -y install zlib1g-dev libgd2-xpm-dev libgeoip-dev

	# ensure that we have the required software to compile opensgx
	sudo apt-get -y build-dep qemu
	sudo apt-get -y install libelf-dev	
}

prepare_fresh() {
	echo "Create necessary folders"
	sudo mkdir -p /var/lib/nginx/body
	if [ ! -d $NGINX_LOG_DIR ]; then
		sudo mkdir $NGINX_LOG_DIR
	fi
	if [ ! -d $BPATH/opensgx/libsgx/libressl/ ]; then
		echo "Copying libressl to opensgx"
		cp -r $STATICLIBSSL/ $BPATH/opensgx/libsgx/libressl/
		cd $BPATH/opensgx/libsgx/libressl/
		make clean
	fi

	CONF="/etc/nginx/nginx.conf"
	MIME="/etc/nginx/mime.types"
	if [ ! -f $CONF ]; then
		echo "Copying default config file"
		sudo cp $CONF.default $CONF
	fi
	if [ ! -f $MIME ]; then
		echo "Copying default mime file"
		sudo cp $MIME.default $MIME
	fi

	# generate certificates if not present
	#from https://www.digitalocean.com/community/tutorials/how-to-create-an-ssl-certificate-on-nginx-for-ubuntu-14-04
	SSL_CRT_DIR="/etc/nginx/ssl"
	if [ ! -d $SSL_CRT_DIR ]; then
		echo "Creating certificates"
		sudo mkdir SSL_CRT_DIR
		sudo printf "GB\nLondon\nLondon\nUCL\nNCS\nlocalhost\nfoo@localhost\n" | openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout $SSL_CRT_DIR/nginx.key -out $SSL_CRT_DIR/nginx.crt
	fi

	cd $BPATH
	cd ..
}


# clean out any files from previous runs of this script
case "$1" in
  -h|--help)
    print_usage
  ;;
  -d|--download)
	download_sources
    ;;
  -n|--nginx)
	build_libressl
	build_nginx
	build_libressl_sgx
  ;;
  --stock)
    build_stock_libressl
    build_stock_nginx
  ;;
  --ns)
	build_libressl_sgx
  ;;
  -s|--sgx)
    build_opensgx
  ;;
  -l)
	build_libressl
  ;;
  --ll)
	echo "Copying changed libressl files"
	$RSYNC_OPTIONS="--include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs"
	rsync -avP --include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs $STATICLIBSSL/crypto/ $BPATH/opensgx/libsgx/libressl/crypto/
	rsync -avP --include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs $STATICLIBSSL/ssl/ $BPATH/opensgx/libsgx/libressl/ssl/
	rsync -avP --include '*/' --include '*.c' --include '*.h' --exclude '*' --prune-empty-dirs $STATICLIBSSL/include/openssl/ $BPATH/opensgx/libsgx/libressl/include/openssl/
	
	build_libressl
	build_libressl_sgx
  ;;
  --lt)
	build_libressl_busywait
  ;;
  -g|--git)
    install_dependencies
    build_opensgx
    buold_libressl
    build_nginx
    prepare_fresh
    build_libressl_sgx

    print_finish
  ;;
  -c|--clean)
	sudo rm -rf build
	mkdir build
  ;&
  *)
	# default case
	sudo rm -rf build
	mkdir build

    install_dependencies
    mkdir build
    download_sources
    build_opensgx
    #build_nginx
    prepare_fresh
    build_libressl_sgx

    print_finish
  ;;
esac



# TODO: apply our patches

# patch nginx to work with neverbleed
# echo "Patch NGINX with neverbleed"
# cd build
# cp neverbleed/neverbleed.c neverbleed/neverbleed.h $VERSION_NGINX/src/event/

# #apply patches
# patch -p 1 -i neverbleed_nginx_patch/nginx_neverbleed.diff
# cd ../
