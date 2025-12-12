// bob.c
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
    fprintf(stderr, "Usage: %s <bob_n.txt> <bob_sk.txt> <server_n.txt>\n",
            argv[0]);
    return 1;
  }

  const char *bob_n_path = argv[1];
  const char *bob_sk_path = argv[2];
  const char *server_n_path = argv[3];
  const char *enc_key_path = "encryption_key.txt";

  mpz_t bob_n, bob_sk, server_n, e;
  mpz_inits(bob_n, bob_sk, server_n, e, NULL);

  if (!read_mpz_hex(bob_n_path, bob_n)) {
    fprintf(stderr, "read bob_n failed\n");
    return 1;
  }
  if (!read_mpz_hex(bob_sk_path, bob_sk)) {
    fprintf(stderr, "read bob_sk failed\n");
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

  /* Generate rB and xB */
  mpz_t rB, xB;
  mpz_inits(rB, xB, NULL);
  rand_mpz_256_mod(rB, server_n, 1);
  rand_mpz_bits(xB, 256);

  /* cB = rB^e mod server_n */
  mpz_t cB;
  mpz_init(cB);
  powmod_square_mul(cB, rB, e, server_n);

  /* Prepare byte buffers for cB and xB (big-endian) */
  char *cB_hex = mpz_get_str(NULL, 16, cB); /* hex string, no 0x, lowercase */
  char *xB_hex = mpz_get_str(NULL, 16, xB);

  size_t cB_bytes_len = 0, xB_bytes_len = 0;
  unsigned char *cB_bytes = hex_to_bytes(cB_hex, &cB_bytes_len);
  unsigned char *xB_bytes = hex_to_bytes(xB_hex, &xB_bytes_len);

  /* Decide FDH output length: size of bob_n in bytes (so FDH maps to group
   * size) */
  size_t fdh_len = 256;

  unsigned char *fdh_out = malloc(fdh_len);
  if (!fdh_out) {
    fprintf(stderr, "fdh alloc fail\n");
    return 1;
  }

  /* Call FDH over concat(cB || xB) */
  if (!fdh_sha256_concat(cB_bytes, cB_bytes_len, xB_bytes, xB_bytes_len,
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
  print_mpz_hex_stderr("Bob - h (FDH)", h);

  /* Compute signature sB = h^{bob_sk} mod bob_n */
  mpz_t sB;
  mpz_init(sB);
  powmod_square_mul(sB, h, bob_sk, bob_n);

  /* Debug print (optional) */
  print_mpz_hex_stderr("Bob - signature", sB);
  printf("\n");

  /* Write outputs in hex */
  if (!write_mpz_hex("ciphertext_bob.txt", cB)) {
    fprintf(stderr, "failed to write ciphertext_bob.txt\n");
    /* continue to cleanup */
  }
  if (!write_mpz_hex("signature_bob.txt", sB)) {
    fprintf(stderr, "failed to write signature_bob.txt\n");
  }
  if (!write_buf_hex("bob_x.txt", xB_bytes, xB_bytes_len)) {
    fprintf(stderr, "failed to write bob_x.txt\n");
  }
  if (!write_mpz_hex("bob_r.txt", rB)) {
    fprintf(stderr, "failed to write bob_r.txt\n");
  }

  /* cleanup */
  mpz_clears(bob_n, bob_sk, server_n, e, rB, xB, cB, h, sB, NULL);
  if (cB_hex)
    free(cB_hex);
  if (xB_hex)
    free(xB_hex);
  if (cB_bytes)
    free(cB_bytes);
  if (xB_bytes)
    free(xB_bytes);
  if (fdh_out)
    free(fdh_out);

  return 0;
}
