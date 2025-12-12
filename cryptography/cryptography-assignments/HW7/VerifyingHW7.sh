#!/bin/bash
set -e

# === Compile all programs ===
echo "Compiling..."
gcc -O2 Alice.c  -o Alice  -lgmp -lcrypto
gcc -O2 Bob.c    -o Bob    -lgmp -lcrypto
gcc -O2 Server.c -o Server -lgmp -lcrypto
echo "Build done."

# === Helper: normalize hex (uppercase, strip leading zeros) ===
normalize_hex() {
  local x="${1^^}"
  # remove any non-hex just in case (safety)
  x="$(printf "%s" "$x" | tr -cd '0-9A-F')"
  # strip leading zeros
  x="${x#"${x%%[!0]*}"}"
  [[ -z "$x" ]] && x="0"
  printf "%s" "$x"
}

# === Run 3 test cases with indexed files ===
for i in 1 2 3
do
    echo "-----------------------------"
    echo " Running Test Case $i"
    echo "-----------------------------"

    # === Alice ===
    # Alice expects: ./Alice alice_n.txt alice_sk.txt server_n.txt
    ./Alice "alice_n_${i}.txt" "alice_sk_${i}.txt" "server_n_${i}.txt"
    if [ ! -f ciphertext_alice.txt ] || [ ! -f signature_alice.txt ] || [ ! -f alice_x.txt ] || [ ! -f alice_r.txt ]; then
        echo "Test case $i failed: Alice output files missing."
        exit 1
    fi

    # === Bob ===
    # Bob expects: ./Bob bob_n.txt bob_sk.txt server_n.txt
    ./Bob "bob_n_${i}.txt" "bob_sk_${i}.txt" "server_n_${i}.txt"
    if [ ! -f ciphertext_bob.txt ] || [ ! -f signature_bob.txt ] || [ ! -f bob_x.txt ] || [ ! -f bob_r.txt ]; then
        echo "Test case $i failed: Bob output files missing."
        exit 1
    fi

    # === Server ===
    # Server expects:
    # ./Server server_n.txt server_sk.txt \
    #          ciphertext_alice.txt signature_alice.txt \
    #          ciphertext_bob.txt   signature_bob.txt   \
    #          alice_x.txt  bob_x.txt  \
    #          alice_n.txt  bob_n.txt
    ./Server "server_n_${i}.txt" "server_sk_${i}.txt" \
             ciphertext_alice.txt signature_alice.txt \
             ciphertext_bob.txt   signature_bob.txt   \
             alice_x.txt bob_x.txt \
             "alice_n_${i}.txt" "bob_n_${i}.txt"

    # // check if decryption.txt exists.
    if [ ! -f decryption.txt ]; then
        echo "Test case $i failed: Server output file missing."
        exit 1
    fi

    # ---- Robust hex readers ----
    read_hex_file() { tr -cd '0-9A-Fa-f' < "$1" | tr '[:lower:]' '[:upper:]'; }

    # compare decryption.txt (exact product) with alice_r.txt * bob_r.txt (NO MOD)
    rA=$(read_hex_file "alice_r.txt")
    rB=$(read_hex_file "bob_r.txt")
    dec=$(read_hex_file "decryption.txt")

    # Correct order: set obase first, then ibase; strip any whitespace/newlines from bc output
    prod_hex=$(echo "obase=16; ibase=16; ${rA} * ${rB}" | bc | tr -cd '0-9A-F')

    norm_dec=$(normalize_hex "$dec")
    norm_prod=$(normalize_hex "$prod_hex")

    if [[ "$norm_dec" != "$norm_prod" ]]; then
        echo "Test case $i failed: decryption.txt != rA * rB"
        echo "Expected: $norm_prod"
        echo "Got:      $norm_dec"
        exit 1
    fi

    echo "Test case $i passed"
    echo "Cleaning up temporary runtime files..."
    rm -f ciphertext_* signature_* *_x.txt *_r.txt server_log.txt
done

echo "=============================================="
echo "All 3 test cases passed successfully."
echo "=============================================="
