#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>


static void handleErrors(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

void fs_key_hex(const char *folder_name, EC_KEY *key) {
    if (!key) handleErrors("fs_key_hex: key is NULL");

    // --- Extract private key ---
    const BIGNUM *priv = EC_KEY_get0_private_key(key);
    if (!priv) handleErrors("fs_key_hex: no private key");
    char *priv_hex = BN_bn2hex(priv);

    // private key file
    char priv_path[512];
    snprintf(priv_path, sizeof(priv_path), "%s/private_key_hex.txt", folder_name);

    FILE *fp = fopen(priv_path, "w");
    if (!fp) handleErrors("Cannot write private_key_hex");
    fprintf(fp, "%s\n", priv_hex);
    fclose(fp);
    OPENSSL_free(priv_hex);

    // --- Extract public key (x,y) ---
    const EC_POINT *pub = EC_KEY_get0_public_key(key);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    if (!pub || !group) handleErrors("fs_key_hex: no public key");

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) handleErrors("BN_CTX_new failed");

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    if (!x || !y) handleErrors("BN_new failed");

    if (!EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, ctx))
        handleErrors("EC_POINT_get_affine_coordinates_GFp failed");

    char *x_hex = BN_bn2hex(x);
    char *y_hex = BN_bn2hex(y);

    // public key file
    char pub_path[512];
    snprintf(pub_path, sizeof(pub_path), "%s/public_key_points.txt", folder_name);

    fp = fopen(pub_path, "w");
    if (!fp) handleErrors("Cannot write public_key_points");
    fprintf(fp, "(%s,%s)\n", x_hex, y_hex);
    fclose(fp);

    const EC_POINT *G = EC_GROUP_get0_generator(group);
    if (!G) handleErrors("EC_GROUP_get0_generator failed");

    if (!EC_POINT_get_affine_coordinates_GFp(group, G, x, y, ctx))
        handleErrors("EC_POINT_get_affine_coordinates_GFp failed for G");

    x_hex = BN_bn2hex(x);
    y_hex = BN_bn2hex(y);

    char gen_path[512];
    snprintf(gen_path, sizeof(gen_path), "generator_point", folder_name);
    fp = fopen(gen_path, "w");
    if (!fp) handleErrors("Cannot write generator_point");
    fprintf(fp, "(%s,%s)\n", x_hex, y_hex);
    fclose(fp);

    // cleanup
    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
    BN_free(x);
    BN_free(y);
    BN_CTX_free(ctx);
}

// Save SHA256 hash of input string into a hex file
void save_hash(const char *input, const char *file_location) {
    unsigned char hash[SHA256_DIGEST_LENGTH];   // 32 bytes
    char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    FILE *fp;

    // Compute SHA256 hash
    SHA256((unsigned char*)input, strlen(input), hash);

    // Convert raw bytes to hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(&hash_hex[i * 2], "%02x", hash[i]);
    hash_hex[SHA256_DIGEST_LENGTH * 2] = '\0';

    // Write hash hex string to file
    fp = fopen(file_location, "w");
    if (!fp) {
        perror("save_hash: Cannot open file");
        return;
    }
    fprintf(fp, "%s\n", hash_hex);
    fclose(fp);

    printf("Hash saved to %s\n", file_location);
}

char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    char *output = (char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

// Write to file
void Write_File(char fileName[], char input[]){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  fputs(input, pFile);
  fclose(pFile);
}

// Show in hex
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

// Convert to hex
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}
