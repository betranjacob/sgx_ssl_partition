#!/usr/bin/env bash

# install cloc
sudo apt-get -y install cloc 

echo "Diffrence in source code lines for libressl:"

cloc --quiet \
     --exclude-lang=make,CMake,Assembly,'Bourne Again Shell','Bourne Shell',m4 \
     --exclude-dir='.openssl' \
     --diff build/libressl-2.4.1.tar.gz build/libressl-2.4.1/

echo "Diffrence in source code lines for nginx:"

cloc --quiet \
     --exclude-lang=make,CMake,Assembly,'Bourne Again Shell','Bourne Shell',m4,HTML,Perl,'vim script',SKILL,C++ \
     --diff build/nginx-1.11.1.tar.gz build/nginx-1.11.1/

#  save those (all languages) into a csv file
cloc --quiet \
     --exclude-lang=make,CMake,Assembly,'Bourne Again Shell','Bourne Shell',m4 \
     --exclude-dir='.openssl' \
     --diff build/libressl-2.4.1.tar.gz build/libressl-2.4.1/ \
     --report-file=./results/libressl_sloc_diff.csv \
     --csv

cloc --quiet \
     --exclude-lang=make,CMake,Assembly,'Bourne Again Shell','Bourne Shell',m4,HTML,Perl,'vim script',SKILL,C++ \
     --diff build/nginx-1.11.1.tar.gz build/nginx-1.11.1/ \
     --report-file=./results/nginx_sloc_diff.csv \
     --csv
