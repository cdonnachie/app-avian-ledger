#!/bin/bash
bash ./clean_tests.sh

# TODO: tests currently not working with DEBUG=1

cd ..
make clean
make -j DEBUG=1 COIN=ravencoin
mv bin/ tests-legacy/ravencoin-bin
