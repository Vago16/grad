#!/bin/bash

gcc alice.c -lssl -lcrypto -o alice &&
gcc bob.c -lssl -lcrypto -o bob &&
# Run Alice
./alice SharedSeed1.txt Messages1.txt &&
# Run Bob
./bob SharedSeed1.txt Ciphertexts.txt
