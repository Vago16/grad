gcc KeyGen.c -lssl -lcrypto -o KeyGen
gcc alice.c -lssl -lcrypto -o Alice
gcc bob.c -lssl -lcrypto -o Bob

echo "--------"
./KeyGen Seed1.txt
echo "--------"
./Alice  PK_Hex.txt alice_sk1.txt Random_k_Hex1.txt Message1.txt
echo "--------"
./Bob SK_Hex.txt alice_pk1.txt alice_c.txt alice_d.txt alice_signature.txt
echo "--------"
