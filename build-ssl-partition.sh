#!/usr/bin/env bash

# adopted from https://gist.github.com/Belphemur/3c022598919e6a1788fc
# includes neverbleed patch

# proc for building faster
NB_PROC=$(grep -c ^processor /proc/cpuinfo)
 
# set the log folder
NGINX_LOG_DIR=/var/log/nginx

# set where LibreSSL and nginx will be built
export BPATH=$(pwd)/build
# export STATICLIBSSL=$BPATH/$VERSION_LIBRESSL

# names of latest versions of each package
export NGINX_VERSION=1.11.1
export VERSION_PCRE=pcre-8.38
export VERSION_LIBRESSL=libressl-2.4.1
export VERSION_NGINX=nginx-$NGINX_VERSION
#export NPS_VERSION=1.9.32.10
#export VERSION_PAGESPEED=v${NPS_VERSION}-beta
 
# URLs to the source directories
export SOURCE_LIBRESSL=http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/
export SOURCE_PCRE=ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/
export SOURCE_NGINX=http://nginx.org/download/
#export SOURCE_RTMP=https://github.com/arut/nginx-rtmp-module.git
#export SOURCE_PAGESPEED=https://github.com/pagespeed/ngx_pagespeed/archive/
export SOURCE_OPENSGX=https://github.com/sslab-gatech/opensgx.git

# print_usage() {
#   cat <<EOF
# [usage] $0 [option]... [binary]
# -a|--all  : test all cases
# -h|--help : print help
# -i|--icount : count the number of executed instructions
# --perf|--performance-measure : measure SGX emulator performance metrics
# [test]    : run a test case
# EOF
#   # for f in test/*.c; do
#   #   printf " %-30s: %s\n" "$f" "$(cat $f| head -1 | sed 's#//##g')"
#   # done
# }


build_nginx() {
	# build static LibreSSL
	echo "Configure & Build LibreSSL"
	STATICLIBSSL=$BPATH/$VERSION_LIBRESSL
	# cd $BPATH/$VERSION_LIBRESSL
	cd $STATICLIBSSL
	# ./configure LDFLAGS=-lrt --prefix=${STATICLIBSSL}/.openssl/ && make install-strip -j $NB_PROC

	#no strip for callgrind
	./configure LDFLAGS="-lrt" CFLAGS="-O0 -g" --enable-shared --prefix=${STATICLIBSSL}/.openssl/ && make install -j $NB_PROC

	# build nginx, with various modules included/excluded
	echo "Configure & Build Nginx"
	cd $BPATH/$VERSION_NGINX

	mkdir -p $BPATH/nginx
	./configure  --with-openssl=$STATICLIBSSL \
	--with-debug \
	--with-ld-opt="-lrt"  \
	--with-cc-opt='-O0 -g' \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=$NGINX_LOG_DIR/error.log \
	--http-log-path=$NGINX_LOG_DIR/access.log \
	--with-pcre=$BPATH/$VERSION_PCRE \
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
	--with-pcre-jit \
	--with-http_stub_status_module \
	--with-http_realip_module \
	--with-http_auth_request_module \
	--with-http_addition_module \
	--with-http_geoip_module \
	--with-http_gzip_static_module
	# --add-module=$BPATH/rtmp
	#--add-module=$BPATH/ngx_pagespeed-${NPS_VERSION}-beta
	# --with-cc-opt='-Wno-error -O0 -g' \

	touch $STATICLIBSSL/.openssl/include/openssl/ssl.h
	# make -j $NB_PROC && sudo checkinstall --pkgname="nginx-libressl" --pkgversion="$NGINX_VERSION" \
	# --provides="nginx" --requires="libc6, libpcre3, zlib1g" --strip=yes \
	# --stripso=yes --backup=yes -y --install=yes

	# dont strip for callgrind
	make -j $NB_PROC && sudo checkinstall --pkgname="nginx-libressl" --pkgversion="$NGINX_VERSION" \
	--provides="nginx" --requires="libc6, libpcre3, zlib1g" --strip=no \
	--stripso=no --backup=yes -y --install=yes
}

build_opensgx() {
	echo "Configure & Build OpenSGX"
	cd $BPATH/opensgx
	# compile opensgx
	# Compile QEMU
	cd qemu
	./configure-arch
	make -j $(NB_PROC)

	# Back to opensgx/
	cd ..

	# Compile sgx library and user-level code
	make -C libsgx
	make -C user

	# create new key
	./opensgx -k

	# back to build, prob not necessary
	cd ../
}

download_sources() {
	# grab the source files
	echo "Download sources"
	# TODO: make sure we include downloaded sources we used in the repo
	wget -P ./build $SOURCE_PCRE$VERSION_PCRE.tar.gz
	wget -P ./build $SOURCE_LIBRESSL$VERSION_LIBRESSL.tar.gz
	wget -P ./build $SOURCE_NGINX$VERSION_NGINX.tar.gz
	git clone $SOURCE_OPENSGX ./build/opensgx
	#wget -P ./build $SOURCE_PAGESPEED$VERSION_PAGESPEED.tar.gz
	#wget -P ./build https://dl.google.com/dl/page-speed/psol/${NPS_VERSION}.tar.gz
	#git clone $SOURCE_RTMP ./build/rtmp
	 
	# expand the source files
	echo "Extract Packages"
	cd build
	tar xzf $VERSION_NGINX.tar.gz
	tar xzf $VERSION_LIBRESSL.tar.gz
	tar xzf $VERSION_PCRE.tar.gz
	#tar xzf $VERSION_PAGESPEED.tar.gz
	#tar xzf ${NPS_VERSION}.tar.gz -C ngx_pagespeed-${NPS_VERSION}-beta
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
}


# clean out any files from previous runs of this script
case "$1" in
  -h|--help)
    echo "TODO: usage"
  ;;
  -d|--download)
	download_sources
    ;;
  -n|--nginx)
	build_nginx
  ;;
  -s|--sgx)
    build_opensgx
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
    build_nginx
    prepare_fresh
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



echo "All done.";
echo "This build has not edited your existing /etc/nginx directory.";
echo "If things aren't working now you may need to refer to the";
echo "configuration files the new nginx ships with as defaults,";
echo "which are available at /etc/nginx-default";