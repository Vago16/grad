#!/bin/bash

mkdir -p bin &&
gcc alice.c -lssl -lcrypto -o bin/alice &&
./bin/alice ./CRP_tests/Message1.txt ./CRP_tests/SharedKey1.txt ./CRP_tests/A_ctr1.txt ./CRP_tests/A_nonce1.txt
