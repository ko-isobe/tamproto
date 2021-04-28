#!/bin/sh

cd /usr/src/app/suit
# install build tool
apk add make g++ libressl-dev 
# QCBOR
cd QCBOR
make install
# t_cose
cd ../t_cose
make -f Makefile.ossl install
# libcsuit
cd ../libcsuit
make -f Makefile.parser test