#!/bin/bash

cp ../opensgx/user/test/openssl/libressl-pipe.c .
cp ../opensgx/user/test/openssl/libressl-pipe.h .
make
sudo ./libressl-pipe libressl-pipe
