/*
 * keygen.c
 * -----------------------------------------------------------------------------
 * Generates key material for ALL parties (HEX), and writes the GLOBAL
 * RSA public exponent to "encryption_key.txt" (one line, HEX).
 *
 * For each of {alice, bob, server}:
 *   - p.txt, q.txt : RSA primes (HEX)
 *   - n.txt        : modulus n = p*q (HEX)
 *   - sk.txt       : private exponent d (HEX)
 *
 * Public key exponent e is global and written ONCE to:
 *   - encryption_key.txt     (HEX, e.g., "010001" for 65537)
 *
 * No *_pk.txt files are written anymore.
 */
/* GMP-based RSA key generation (2048-bit modulus) */
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "RequiredFunctions.c"

/* Set your global public exponent here (HEX). Typically 65537 -> "010001". */
static const char *GLOBAL_RSA_PK_E_HEX = "010001"; /* 65537 */

static int make_party(const char *p_path,const char *q_path,
                      const char *n_path,const char *sk_path,
                      const mpz_t e)
{
    mpz_t p,q,n,p1,q1,phi,g,d; 
    mpz_inits(p,q,n,p1,q1,phi,g,d,NULL);

    /* Generate two 1024-bit primes -> 2048-bit modulus */
    rand_prime_bits(p, 1024);
    rand_prime_bits(q, 1024);

    mpz_mul(n, p, q);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(phi, p1, q1);

    mpz_gcd(g, e, phi);
    if (mpz_cmp_ui(g,1) != 0) {
        fprintf(stderr, "Error: e not coprime to phi\n");
        mpz_clears(p,q,n,p1,q1,phi,g,d,NULL); return 0;
    }
    if (!mpz_modinv_eea(d, e, phi)) {
        fprintf(stderr, "Failed to compute modular inverse\n");
        mpz_clears(p,q,n,p1,q1,phi,g,d,NULL); return 0;
    }

    if (!write_mpz_hex(p_path,p) || !write_mpz_hex(q_path,q) ||
        !write_mpz_hex(n_path,n) || !write_mpz_hex(sk_path,d)) {
        fprintf(stderr, "File write error\n");
        mpz_clears(p,q,n,p1,q1,phi,g,d,NULL); return 0;
    }

    mpz_clears(p,q,n,p1,q1,phi,g,d,NULL);
    return 1;
}

int main(void) {
    mpz_t e; mpz_init(e);
    if (mpz_set_str(e, GLOBAL_RSA_PK_E_HEX, 16) != 0) {
        fprintf(stderr, "Failed to parse global exponent\n");
        mpz_clear(e); return 1;
    }
    if (!write_mpz_hex("encryption_key.txt", e)) {
        fprintf(stderr, "Failed writing encryption_key.txt\n");
        mpz_clear(e); return 1;
    }
    if (!make_party("alice_p.txt","alice_q.txt","alice_n.txt","alice_sk.txt", e)) { mpz_clear(e); return 1; }
    if (!make_party("bob_p.txt","bob_q.txt","bob_n.txt","bob_sk.txt", e)) { mpz_clear(e); return 1; }
    if (!make_party("server_p.txt","server_q.txt","server_n.txt","server_sk.txt", e)) { mpz_clear(e); return 1; }
    mpz_clear(e);
    printf("keygen (GMP): generated 2048-bit RSA keys for alice, bob, server.\n");
    return 0;
}
