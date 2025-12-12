#include<stdio.h>
#include <stdlib.h>
#include<string.h>
#include <unistd.h>
#include <sys/stat.h>
// openssl imports
#include<openssl/hmac.h>
#include<openssl/sha.h>
#include<openssl/evp.h>

#define DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define DEBUG 0

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen, const char *errorMsg);
void Write_File(char fileName[], char input[]);
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out);
void XOR_32(const unsigned char* in1, const unsigned char *in2, unsigned char *result);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Convert_To_Uchar(char* input_hex, unsigned char output[], int output_len);

int main(int argc, char *argv[]){
  if (DEBUG) printf("------------------ DEBUG LOGS --------------------\n");

  // Read data from files
  int messageLen, keyLen, ctrLen, nonceLen;
  const char *defaultErrorMsg = "Error opening file.";
  unsigned char *message = Read_File (argv[1], &messageLen, defaultErrorMsg);
  unsigned char *key = Read_File (argv[2], &keyLen, defaultErrorMsg);
  unsigned char *ctr = Read_File (argv[3], &ctrLen, defaultErrorMsg);
  unsigned char *nonce = Read_File (argv[4], &nonceLen, defaultErrorMsg);
  int ctrAsInt = atoi((const char *)ctr);
  int nonceAsInt = atoi((const char *)nonce);

  // Logging
  if (DEBUG) {
    printf("MESSAGE (%s, %d bytes):\t\t'%s'\n", argv[1], messageLen, message);
    printf("SHARED KEY (%s, %d bytes):\t'%s'\n", argv[2], keyLen, key);
    printf("COUNTER (%s, %d bytes):\t\t'%s'\n", argv[3], ctrLen, ctr);
    printf("NONCE (%s, %d bytes):\t\t'%s'\n\n", argv[4], nonceLen, nonce);
  }

  // Convert key to hex for Key.txt (allocate +1 for null terminator)
  char keyAsHex[keyLen * 2 + 1];
  Convert_to_Hex(keyAsHex, key, keyLen);
  if (DEBUG) printf("KEY AS HEX: \t\t\t\t\t\t\t%s\n", keyAsHex);
  Write_File("Key.txt", keyAsHex);

  // keystream = SHA256(key || ctr)
  int keyPlusCtrLen = keyLen + ctrLen;
  unsigned char keyPlusCtr[keyPlusCtrLen + 1];
  Concatenation(key, keyLen, ctr, ctrLen, keyPlusCtr);
  keyPlusCtr[keyPlusCtrLen] = '\0'; // safe printing null-terminate
  free(ctr);
  unsigned char keystream[DIGEST_LENGTH];
  SHA256((const unsigned char *)keyPlusCtr, keyPlusCtrLen, keystream);

  // XOR message with keystream to get ciphertext (message must be 32 bytes for this protocol)
  unsigned char ciphertext[DIGEST_LENGTH];
  XOR_32(message, keystream, ciphertext);
  
  // Hex the ciphertext for logging
  char ciphertextAsHex[DIGEST_LENGTH * 2 + 1];
  Convert_to_Hex(ciphertextAsHex, ciphertext, DIGEST_LENGTH);
  if (DEBUG)  printf("CIPHERTEXT -> MESSAGE ⊕ KEYSTREAM: \t\t\t\t%s\n", ciphertextAsHex);
  Write_File("Ciphertext.txt", ciphertextAsHex);

  // CIPHERTEXT || NONCE
  int ciphertextPlusNonceLen = DIGEST_LENGTH + nonceLen;
  unsigned char ciphertextPlusNonce[ciphertextPlusNonceLen];
  Concatenation(ciphertext, DIGEST_LENGTH, nonce, nonceLen, ciphertextPlusNonce);
  free(nonce);

  // HMAC(KEY, CIPHERTEXT || NONCE) to generate signature
  unsigned char res[EVP_MAX_MD_SIZE];
  unsigned int res_len = 0;
  HMAC(EVP_sha256(), key, keyLen, ciphertextPlusNonce, ciphertextPlusNonceLen, res, &res_len);
  free(key);

  // Hex the signature for logging
  char signatureAsHex[res_len * 2 + 1];
  Convert_to_Hex(signatureAsHex, res, res_len);
  if (DEBUG) printf("SIGNATURE  -> HMAC(KEY, CIPHERTEXT || NONCE): \t\t\t%s\n", signatureAsHex);
  Write_File("Signature.txt", signatureAsHex);

  // If a Response.txt from Bob exists read it contents
  int bobResponseLen;
  unsigned char *bobResponse = Read_File("Response.txt", &bobResponseLen, "Bob hasn't responsed yet!");

  // response = SHA256(m || (ctr + 1) || (nonce + 1)).
  unsigned char ctrPlusOne[10];
  snprintf((char *)ctrPlusOne, sizeof(ctrPlusOne), "%d", ctrAsInt + 1); // Convert integer to string
  unsigned char noncePlusOne[10];
  snprintf((char *)noncePlusOne, sizeof(noncePlusOne), "%d", nonceAsInt + 1); // Convert integer to string
  int ctrPlusOneLen = strlen((char *)ctrPlusOne);
  int noncePlusOneLen = strlen((char *)noncePlusOne);

  int messagePlusCtrLen = messageLen + ctrPlusOneLen;
  unsigned char messagePlusCtr[messagePlusCtrLen];
  Concatenation(message, messageLen, ctrPlusOne, ctrPlusOneLen, messagePlusCtr);
  free(message);

  int messagePlusCtrPlusNonceLen = messagePlusCtrLen + noncePlusOneLen;
  unsigned char messagePlusCtrPlusNonce[messagePlusCtrPlusNonceLen];
  Concatenation(messagePlusCtr, messagePlusCtrLen, noncePlusOne, noncePlusOneLen, messagePlusCtrPlusNonce);

  unsigned char response[DIGEST_LENGTH];
  SHA256((const unsigned char *)messagePlusCtrPlusNonce, messagePlusCtrPlusNonceLen, response);

  // Hex the response for logging
  char responseAsHex[DIGEST_LENGTH * 2 + 1];
  Convert_to_Hex(responseAsHex, response, DIGEST_LENGTH);
  if (DEBUG)  printf("RESPONSE  -> SHA256(MESSAGE || (COUNTER + 1) || (NONCE + 1)): \t%s\n", responseAsHex);

  // Increment counter and nonce files
  Write_File("A_ctr.txt", (char *)ctrPlusOne);
  Write_File("A_nonce.txt", (char *)noncePlusOne);

  // Compare signatures
  // Alice writes “Acknowledgment Successful” in a file called “Acknowledgment.txt".
  // Conversely, if the comparison fails, she records “Acknowledgment Failed.”
  if (strcmp((const char *)responseAsHex, (const char *)bobResponse) != 0) {
    Write_File("Acknowledgement.txt", "Acknowledgment Failed.");
    puts("Acknowledgment Failed.");
    if (DEBUG) printf("--------------- END OF DEBUG LOGS ----------------\n");
    // END OF PROGRAM
    return 0;
  }

  Write_File("Acknowledgement.txt", "Acknowledgment Successful.");
  puts("Acknowledgment Successful.");
  if (DEBUG) printf("--------------- END OF DEBUG LOGS ----------------\n");
  // END OF PROGRAM
  return 0;
}

/*============================
    Read from file (binary-safe)
   Strips a single trailing '\n' and/or '\r' if present.
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen, const char *errorMsg)
{
  FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("%s\n", errorMsg);
    if (DEBUG) printf("--------------- END OF DEBUG LOGS ----------------\n");
		exit(0);
	}
  fseek(pFile, 0L, SEEK_END);
  int temp_size = ftell(pFile)+1;
  fseek(pFile, 0L, SEEK_SET);
  unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets((char *)output, temp_size, pFile);
	fclose(pFile);

  *fileLen = temp_size-1;
	return output;
}

/*============================
        Write to File
==============================*/
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

/*============================
    Concatenate two binary buffers into out (out must have in1len+in2len bytes available)
==============================*/
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out){
  memcpy(out, in1, in1len);
  memcpy(out + in1len, in2, in2len);
}

/*============================
    Convert to hex string (output must have at least inputlength*2 + 1 bytes)
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
  for (int i=0; i<inputlength; i++){
    sprintf(&output[2*i], "%02x", input[i]);
  }
  output[2*inputlength] = '\0';
}

/*===================================
    Convert from Hex to unsigned char 
=====================================*/
void Convert_To_Uchar(char* input_hex, unsigned char output[], int output_len)
{   
    for(int i=0; i<output_len; i++){
        unsigned char tmp[2];
        tmp[0]= input_hex[2*i];
        tmp[1]= input_hex[2*i+1];
        output[i] = (unsigned char)strtol((const char *)tmp, NULL, 16);
    }
}

/*============================
    XOR 32 bytes
==============================*/
void XOR_32(const unsigned char* in1, const unsigned char *in2, unsigned char *result) {
  for (size_t i = 0; i < 32; i++) {
    result[i] = in1[i] ^ in2[i];
  }
}
