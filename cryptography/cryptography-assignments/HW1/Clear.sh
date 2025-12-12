#!/bin/bash

rm -f ./CRP_tests/A_ctr1.txt &&
rm -f ./CRP_tests/B_ctr1.txt &&
rm -f ./CRP_tests/A_nonce1.txt &&
rm -f ./CRP_tests/B_nonce1.txt &&
rm -f ./Key.txt &&
rm -f ./Ciphertext.txt &&
rm -f ./Signature.txt &&
rm -f ./Response.txt &&
rm -f ./Acknowledgement.txt &&

echo -n "1" > ./CRP_tests/A_ctr1.txt &&
echo -n "1" > ./CRP_tests/B_ctr1.txt &&
echo -n "55" > ./CRP_tests/A_nonce1.txt &&
echo -n "55" > ./CRP_tests/B_nonce1.txt
