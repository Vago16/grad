#!/bin/bash

mkdir -p bin &&
gcc bob.c -lssl -lcrypto -o bin/bob &&
./bin/bob ./Ciphertext.txt ./Signature.txt ./CRP_tests/SharedKey1.txt ./CRP_tests/B_ctr1.txt ./CRP_tests/B_nonce1.txt
