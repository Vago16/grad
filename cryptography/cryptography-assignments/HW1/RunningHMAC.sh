#!/bin/bash

mkdir -p bin &&
gcc hmac.c -lssl -lcrypto -o bin/hmac &&
./bin/hmac ./HMAC_tests/Message1.txt ./HMAC_tests/SharedKey1.txt
