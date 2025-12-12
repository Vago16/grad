#!/bin/bash

gcc shamirgen.c -lssl -lcrypto -o gen &&
gcc shamirrecon.c -lssl -lcrypto -o recon &&
  
rm -f Share*.txt &&
rm -f Recovered.txt &&

# Run gen
echo "Running generator..." &&
./gen Secret3.txt Modulus3.txt &&

# Run recon
echo "Running reconstructor..." &&
./recon Modulus3.txt
