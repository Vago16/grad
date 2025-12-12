// Alice.c
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "RequiredFunctions.c"

/* Helper: convert hex string (from mpz_get_str) to bytes (big-endian) */
unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
  size_t hexlen = strlen(hex);
  /* mpz_get_str may produce a leading '-' for negative numbers; not expected
   * here */
  if (hexlen == 0) {
    *out_len = 0;
    return NULL;
  }
  /* if odd length, treat as if prefixed with a '0' */
  int need_leading = (hexlen % 2 != 0);
  size_t bytes_len = (hexlen + need_leading) / 2;
  unsigned char *buf = malloc(bytes_len);
  if (!buf) {
    *out_len = 0;
    return NULL;
  }
  size_t hex_idx = 0;
  size_t buf_idx = 0;
  if (need_leading) {
    /* first byte is from single hex digit */
    unsigned int v;
    sscanf(hex + 0, "%1x", &v);
    buf[buf_idx++] = (unsigned char)v;
    hex_idx = 1;
  }
  for (; hex_idx < hexlen; hex_idx += 2) {
    unsigned int v;
    sscanf(hex + hex_idx, "%2x", &v);
    buf[buf_idx++] = (unsigned char)v;
  }
  *out_len = bytes_len;
  return buf;
}

static void print_mpz_hex_stderr(const char *label, const mpz_t v) {
  char *s = mpz_get_str(NULL, 16, v);
  if (s) {
    fprintf(stderr, "%s: 0x%s\n", label, s);
    free(s);
  }
}

int main(int argc, char **argv) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s <alice_n.txt> <alice_sk.txt> <server_n.txt>\n",
            argv[0]);
    return 1;
  }

  const char *alice_n_path = argv[1];
  const char *alice_sk_path = argv[2];
  const char *server_n_path = argv[3];
  const char *enc_key_path = "encryption_key.txt";

  mpz_t alice_n, alice_sk, server_n, e;
  mpz_inits(alice_n, alice_sk, server_n, e, NULL);

  if (!read_mpz_hex(alice_n_path, alice_n)) {
    fprintf(stderr, "read alice_n failed\n");
    return 1;
  }
  if (!read_mpz_hex(alice_sk_path, alice_sk)) {
    fprintf(stderr, "read alice_sk failed\n");
    return 1;
  }
  if (!read_mpz_hex(server_n_path, server_n)) {
    fprintf(stderr, "read server_n failed\n");
    return 1;
  }
  if (!read_mpz_hex(enc_key_path, e)) {
    fprintf(stderr, "read encryption key failed (%s)\n", enc_key_path);
    return 1;
  }

  /* Generate rA and xA */
  mpz_t rA, xA;
  mpz_inits(rA, xA, NULL);
  rand_mpz_256_mod(rA, server_n, 1);
  rand_mpz_bits(xA, 256);

  /* cA = rA^e mod server_n */
  mpz_t cA;
  mpz_init(cA);
  powmod_square_mul(cA, rA, e, server_n);

  /* Prepare byte buffers for cA and xA (big-endian) */
  char *cA_hex = mpz_get_str(NULL, 16, cA); /* hex string, no 0x, lowercase */
  char *xA_hex = mpz_get_str(NULL, 16, xA);

  size_t cA_bytes_len = 0, xA_bytes_len = 0;
  unsigned char *cA_bytes = hex_to_bytes(cA_hex, &cA_bytes_len);
  unsigned char *xA_bytes = hex_to_bytes(xA_hex, &xA_bytes_len);

  /* Decide FDH output length: size of alice_n in bytes (so FDH maps to group
   * size) */
  size_t fdh_len = 256;

  unsigned char *fdh_out = malloc(fdh_len);
  if (!fdh_out) {
    fprintf(stderr, "fdh alloc fail\n");
    return 1;
  }

  /* Call FDH over concat(cA || xA) */
  if (!fdh_sha256_concat(cA_bytes, cA_bytes_len, xA_bytes, xA_bytes_len,
                         fdh_len, fdh_out)) {
    fprintf(stderr, "fdh_sha256_concat failed\n");
    return 1;
  }

  /* Import FDH output into mpz_t h (big-endian) */
  mpz_t h;
  mpz_init(h);
  /* mpz_import: count = fdh_len, order=1 (most significant word first), size=1,
     endian=0 (native within word) — with size=1 endian doesn't matter */
  mpz_import(h, fdh_len, 1, 1, 0, 0, fdh_out);

  /* Debug print (optional) */
  print_mpz_hex_stderr("Alice - h (FDH)", h);

  /* Compute signature sA = h^{alice_sk} mod alice_n */
  mpz_t sA;
  mpz_init(sA);
  powmod_square_mul(sA, h, alice_sk, alice_n);

  /* Debug print (optional) */
  print_mpz_hex_stderr("Alice - signature", sA);
  printf("\n");

  /* Write outputs in hex */
  if (!write_mpz_hex("ciphertext_alice.txt", cA)) {
    fprintf(stderr, "failed to write ciphertext_alice.txt\n");
    /* continue to cleanup */
  }
  if (!write_mpz_hex("signature_alice.txt", sA)) {
    fprintf(stderr, "failed to write signature_alice.txt\n");
  }
  if (!write_buf_hex("alice_x.txt", xA_bytes, xA_bytes_len)) {
    fprintf(stderr, "failed to write alice_x.txt\n");
  }
  if (!write_mpz_hex("alice_r.txt", rA)) {
    fprintf(stderr, "failed to write alice_r.txt\n");
  }

  /* cleanup */
  mpz_clears(alice_n, alice_sk, server_n, e, rA, xA, cA, h, sA, NULL);
  if (cA_hex)
    free(cA_hex);
  if (xA_hex)
    free(xA_hex);
  if (cA_bytes)
    free(cA_bytes);
  if (xA_bytes)
    free(xA_bytes);
  if (fdh_out)
    free(fdh_out);

  return 0;
}
