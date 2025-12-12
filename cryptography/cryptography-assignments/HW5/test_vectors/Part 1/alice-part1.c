#include <ctype.h>
#include <oqs/common.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <oqs/oqs.h>

// Function definitions
uint8_t *Read_Hex_File(const char *filename, size_t *data_len);
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len);

int main(int argc, char *argv[]) {
  /* Setup Variables */
  int exit_code = EXIT_FAILURE;
  uint8_t *bob_kyber_public;
  uint8_t *alice_dilithium_private;
  OQS_KEM *kem;
  uint8_t *ct;
  uint8_t *shared_secret;
  OQS_SIG *sig;
  uint8_t *signature;

  /* Initialize liboqs library */
  OQS_init();

  /* Read Bob's Kyber public key (hex file -> bytes) */
  size_t bob_kyber_public_len;
  bob_kyber_public = Read_Hex_File(argv[1], &bob_kyber_public_len);
  if (!bob_kyber_public) {
    fprintf(stderr, "ERROR: Failed to read Bob's Kyber public key file.\n");
    goto cleanup;
  }

  /* Create KEM object for Kyber512 */
  kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
  if (kem == NULL) {
    fprintf(stderr, "ERROR: OQS_KEM_new failed for %s\n",
            OQS_KEM_alg_kyber_512);
    goto cleanup;
  }

  /* Verify length of Bob's public key matches expected length */
  if (bob_kyber_public_len != (size_t)kem->length_public_key) {
    fprintf(stderr,
            "ERROR: Bob's Kyber public key length mismatch: got %zu, expected "
            "%zu\n",
            bob_kyber_public_len, kem->length_public_key);
    goto cleanup;
  }

  /* Read Alice's Dilithium secret key (hex file -> bytes) */
  size_t alice_dilithium_private_len;
  alice_dilithium_private =
      Read_Hex_File(argv[2], &alice_dilithium_private_len);
  if (!alice_dilithium_private) {
    fprintf(stderr,
            "ERROR: Failed to read Alice's Dilithium private key file.\n");
    goto cleanup;
  }

  /* Allocate buffers for ciphertext and shared secret */
  ct = malloc(kem->length_ciphertext);
  shared_secret = malloc(kem->length_shared_secret);
  if (!ct || !shared_secret) {
    fprintf(stderr, "ERROR: Failed to allocate KEM buffers\n");
    goto cleanup;
  }

  /* Perform encapsulation: (CTA, K1A) = Kyber.Encaps(pk_bob) */
  if (OQS_KEM_encaps(kem, ct, shared_secret, bob_kyber_public) != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_KEM_encaps failed\n");
    goto cleanup;
  }

  /* Create signature object for Dilithium2 */
  sig = OQS_SIG_new("Dilithium2");
  if (sig == NULL) {
    fprintf(stderr, "ERROR: OQS_SIG_new failed for Dilithium2\n");
    goto cleanup;
  }

  /* Verify length of Alice's Dilithium secret key matches expected length */
  if (alice_dilithium_private_len != (size_t)sig->length_secret_key) {
    fprintf(stderr,
            "ERROR: Alice's Dilithium secret key length mismatch: got %zu, "
            "expected %zu\n",
            alice_dilithium_private_len, sig->length_secret_key);
    goto cleanup;
  }

  /* Sign the ciphertext (CTA) with Alice's Dilithium private key */
  signature = malloc(sig->length_signature);
  size_t signature_len = 0;
  if (!signature) {
    fprintf(stderr, "ERROR: Failed to allocate signature buffer\n");
    goto cleanup;
  }

  if (OQS_SIG_sign(sig, signature, &signature_len, ct, kem->length_ciphertext,
                   alice_dilithium_private) != OQS_SUCCESS) {
    fprintf(stderr, "ERROR: OQS_SIG_sign failed\n");
    goto cleanup;
  }

  /* Write outputs as hex files */
  Write_Hex_File("kyber_ciphertext.txt", ct, kem->length_ciphertext);
  Write_Hex_File("dilithium_signature.txt", signature, signature_len);
  Write_Hex_File("alice_shared_secret.txt", shared_secret,
                 kem->length_shared_secret);

  exit_code = EXIT_SUCCESS;

cleanup:
  /* Clean up */
  if (signature)
    free(signature);
  if (sig)
    OQS_SIG_free(sig);
  if (ct)
    free(ct);
  if (shared_secret)
    free(shared_secret);
  if (kem)
    OQS_KEM_free(kem);
  if (bob_kyber_public)
    free(bob_kyber_public);
  if (alice_dilithium_private)
    free(alice_dilithium_private);
  /* Shutdown liboqs */
  OQS_destroy();
  return exit_code;
}

// Read file content
char *Read_File(const char *filename, long *fileLen) {
  FILE *file = fopen(filename, "rb");
  if (!file) {
    fprintf(stderr, "Error: Cannot open file %s\n", filename);
    return NULL;
  }
  fseek(file, 0, SEEK_END);
  *fileLen = ftell(file);
  fseek(file, 0, SEEK_SET);
  char *content = malloc(*fileLen + 1);
  if (!content) {
    fclose(file);
    return NULL;
  }
  fread(content, 1, *fileLen, file);
  content[*fileLen] = '\0';
  fclose(file);
  return content;
}

// Convert hex string to bytes
int Convert_from_Hex(uint8_t *output, const char *hex_input, size_t max_len) {
  size_t hex_len = strlen(hex_input);
  int bytes = 0;
  for (size_t i = 0; i < hex_len; i += 2) {
    if (!isxdigit(hex_input[i]) || !isxdigit(hex_input[i + 1])) {
      continue;
    }
    if (bytes >= max_len)
      break;
    sscanf(&hex_input[i], "%2hhx", &output[bytes]);
    bytes++;
  }
  return bytes;
}

// Read hex file
uint8_t *Read_Hex_File(const char *filename, size_t *data_len) {
  long file_len;
  char *content = Read_File(filename, &file_len);
  if (!content) {
    *data_len = 0;
    return NULL;
  }
  uint8_t *data = malloc(file_len / 2 + 1);
  if (!data) {
    free(content);
    *data_len = 0;
    return NULL;
  }
  *data_len = Convert_from_Hex(data, content, file_len / 2 + 1);
  free(content);
  if (*data_len == 0) {
    free(data);
    return NULL;
  }
  return data;
}

// Write to file
void Write_File(const char *filename, const char *content) {
  FILE *file = fopen(filename, "w");
  if (!file) {
    fprintf(stderr, "Error: Cannot write to %s\n", filename);
    return;
  }
  fputs(content, file);
  fclose(file);
}

// Convert bytes to hex string
void Convert_to_Hex(char *output, const uint8_t *input, size_t len) {
  for (size_t i = 0; i < len; i++) {
    sprintf(output + 2 * i, "%02X", input[i]);
  }
  output[len * 2] = '\0';
}

// Write hex file
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len) {
  char *hex_str = malloc(len * 2 + 1);
  if (!hex_str)
    return;
  Convert_to_Hex(hex_str, data, len);
  Write_File(filename, hex_str);
  free(hex_str);
}
