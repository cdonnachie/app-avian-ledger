#!/bin/bash
bash ./clean_tests.sh

# TODO: tests currently not working with DEBUG=1

cd ..
make clean
make -j DEBUG=0 COIN=ravencoin
mv bin/ tests-legacy/ravencoin-bin
make clean
make -j DEBUG=0 COIN=ravencoin_testnet_lib
mv bin/ tests-legacy/ravencoin-testnet-bin
