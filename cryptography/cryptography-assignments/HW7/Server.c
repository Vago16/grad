// Server.c
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

static void print_hex_buf_stderr(const char *label, const unsigned char *buf,
                                 size_t len) {
  fprintf(stderr, "%s (len=%zu): ", label, len);
  for (size_t i = 0; i < len; ++i)
    fprintf(stderr, "%02X", buf[i]);
  fprintf(stderr, "\n");
}

static void print_mpz_hex_stderr(const char *label, const mpz_t v) {
  char *s = mpz_get_str(NULL, 16, v);
  if (s) {
    fprintf(stderr, "%s: 0x%s\n", label, s);
    free(s);
  }
}

int main(int argc, char *argv[]) {
  if (argc != 11) {
    fprintf(stderr,
            "Usage: %s <server_n> <server_sk> <cA> <sA> <cB> <sB> <alice_x> "
            "<bob_x> <alice_n> <bob_n>\n",
            argv[0]);
    return 1;
  }

  const char *server_n_path = argv[1];
  const char *server_sk_path = argv[2];
  const char *cA_path = argv[3];
  const char *sA_path = argv[4];
  const char *cB_path = argv[5];
  const char *sB_path = argv[6];
  const char *alice_x_path = argv[7];
  const char *bob_x_path = argv[8];
  const char *alice_n_path = argv[9];
  const char *bob_n_path = argv[10];
  const char *enc_key_path = "encryption_key.txt";

  mpz_t server_n, server_sk, sA, sB, alice_n, bob_n, e;
  mpz_inits(server_n, server_sk, sA, sB, alice_n, bob_n, e, NULL);

  if (!read_mpz_hex(server_n_path, server_n)) {
    fprintf(stderr, "read server_n failed\n");
    goto fail;
  }
  if (!read_mpz_hex(server_sk_path, server_sk)) {
    fprintf(stderr, "read server_sk failed\n");
    goto fail;
  }

  if (!read_mpz_hex(sA_path, sA)) {
    fprintf(stderr, "read sA failed\n");
    goto fail;
  }
  if (!read_mpz_hex(sB_path, sB)) {
    fprintf(stderr, "read sB failed\n");
    goto fail;
  }

  /* ciphertexts as mpz (Alice/Bob wrote mpz hex) */
  mpz_t cA_mpz, cB_mpz;
  mpz_inits(cA_mpz, cB_mpz, NULL);
  if (!read_mpz_hex(cA_path, cA_mpz)) {
    fprintf(stderr, "read cA mpz failed\n");
    goto fail_mpz;
  }
  if (!read_mpz_hex(cB_path, cB_mpz)) {
    fprintf(stderr, "read cB mpz failed\n");
    goto fail_mpz;
  }

  /* read x buffers (raw bytes) */
  unsigned char *alice_x_buf = NULL, *bob_x_buf = NULL;
  size_t alice_x_len = 0, bob_x_len = 0;
  if (!read_buf_hex(alice_x_path, &alice_x_buf, &alice_x_len)) {
    fprintf(stderr, "read alice_x_buf failed\n");
    goto fail_mpz;
  }
  if (!read_buf_hex(bob_x_path, &bob_x_buf, &bob_x_len)) {
    fprintf(stderr, "read bob_x_buf failed\n");
    goto fail_bufs;
  }

  if (!read_mpz_hex(alice_n_path, alice_n)) {
    fprintf(stderr, "read alice_n failed\n");
    goto fail_bufs;
  }
  if (!read_mpz_hex(bob_n_path, bob_n)) {
    fprintf(stderr, "read bob_n failed\n");
    goto fail_bufs;
  }

  if (!read_mpz_hex(enc_key_path, e)) {
    fprintf(stderr, "read enc key failed (%s)\n", enc_key_path);
    goto fail_bufs;
  }

  size_t fdh_len = 256;

  /* Export cA as fixed-length server_nbytes */
  char *cA_hex = mpz_get_str(NULL, 16, cA_mpz);
  size_t cA_bytes_len = 0;
  unsigned char *cA_buf = hex_to_bytes(cA_hex, &cA_bytes_len);
  if (!cA_buf) {
    fprintf(stderr, "export cA fixed failed\n");
    goto fail_bufs;
  }

  /* FDH for Alice: output length == alice_n bytes */
  unsigned char *alice_fdh = malloc(fdh_len);
  if (!alice_fdh) {
    fprintf(stderr, "fdh alloc fail\n");
    return 1;
  }
  if (!fdh_sha256_concat(cA_buf, cA_bytes_len, alice_x_buf, alice_x_len,
                         fdh_len, alice_fdh)) {
    fprintf(stderr, "fdh alice failed\n");
    goto fail_all;
  }

  mpz_t hA, expect_hA;
  mpz_inits(hA, expect_hA, NULL);
  mpz_import(hA, fdh_len, 1, 1, 1, 0, alice_fdh);
  powmod_square_mul(expect_hA, sA, e, alice_n);

  /* debug */
  puts("Server computed FDH for Alice:");
  print_mpz_hex_stderr("alice_signature", sA);
  print_hex_buf_stderr("alice_fdh_bytes", alice_fdh, fdh_len);
  print_mpz_hex_stderr("hA (FDH as mpz)", hA);
  print_mpz_hex_stderr("expect_hA (sA^e mod alice_n)", expect_hA);

  if (mpz_cmp(hA, expect_hA) != 0) {
    fprintf(stderr, "Invalid signature for Alice\n");
    goto fail_all;
  }

  /* Export cB as fixed-length server_nbytes */
  char *cB_hex = mpz_get_str(NULL, 16, cB_mpz);
  size_t cB_bytes_len = 0;
  unsigned char *cB_buf = hex_to_bytes(cB_hex, &cB_bytes_len);
  if (!cB_buf) {
    fprintf(stderr, "export cB fixed failed\n");
    goto fail_bufs;
  }

  /* FDH for Bob */
  unsigned char *bob_fdh = malloc(fdh_len);
  if (!alice_fdh) {
    fprintf(stderr, "fdh alloc fail\n");
    return 1;
  }
  if (!fdh_sha256_concat(cB_buf, cB_bytes_len, bob_x_buf, bob_x_len, fdh_len,
                         bob_fdh)) {
    fprintf(stderr, "fdh bob failed\n");
    goto fail_all;
  }

  mpz_t hB, expect_hB;
  mpz_inits(hB, expect_hB, NULL);
  mpz_import(hB, fdh_len, 1, 1, 1, 0, bob_fdh);
  powmod_square_mul(expect_hB, sB, e, bob_n);

  /* debug */
  puts("Server computed FDH for Bob:");
  print_mpz_hex_stderr("bob_signature", sB);
  print_hex_buf_stderr("bob_fdh_bytes", bob_fdh, fdh_len);
  print_mpz_hex_stderr("hB (FDH as mpz)", hB);
  print_mpz_hex_stderr("expect_hB (sB^e mod bob_n)", expect_hB);

  if (mpz_cmp(hB, expect_hB) != 0) {
    fprintf(stderr, "Invalid signature for Bob\n");
    goto fail_all;
  }

  /* combine and decrypt */
  mpz_t C, M;
  mpz_inits(C, M, NULL);
  mpz_mul(C, cA_mpz, cB_mpz);
  mpz_mod(C, C, server_n);
  powmod_square_mul(M, C, server_sk, server_n);

  write_mpz_hex("decryption.txt", M);
  printf("Server: wrote decryption.txt\n");

  /* cleanup success */
  mpz_clears(server_n, server_sk, sA, sB, alice_n, bob_n, e, NULL);
  mpz_clears(cA_mpz, cB_mpz, hA, expect_hA, hB, expect_hB, C, M, NULL);
  free(cA_buf);
  free(cB_buf);
  free(alice_x_buf);
  free(bob_x_buf);
  free(alice_fdh);
  free(bob_fdh);
  return 0;

/* error cleanup */
fail_all:
  mpz_clears(cA_mpz, cB_mpz, NULL);
  if (cA_buf)
    free(cA_buf);
  if (cB_buf)
    free(cB_buf);
fail_bufs:
  if (alice_x_buf)
    free(alice_x_buf);
  if (bob_x_buf)
    free(bob_x_buf);
fail_mpz:
  mpz_clears(server_n, server_sk, sA, sB, alice_n, bob_n, e, NULL);
fail:
  return 1;
}
