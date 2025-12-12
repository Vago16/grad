#include <stdio.h>
#include <stdlib.h>
#include <string.h> // for memcpy()
#include <unistd.h> // for ssize_t
#include <openssl/sha.h>    // for SHA256()
#include <openssl/evp.h> 

// maximum size of each line that Read/Write_multiple_lines() works with
#define LENGTH_OF_EACH_MESSAGE 64
// number of messages per file in ChainCrypt
#define NUMBER_OF_MESSAGES 4

// Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][LENGTH_OF_EACH_MESSAGE * 2], int num);
void Write_Multiple_Lines_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE+1], int num);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Convert_To_Uchar(char* input_hex, unsigned char output_uchar[], int output_uchar_length);
unsigned char *SHA256(const unsigned char *data, size_t count, unsigned char *md_buf);
void AES256CTR_Decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output);

int main(int argc, char *argv[])
{
  int shared_seed_len;
  unsigned char *shared_seed = Read_File(argv[1], &shared_seed_len);
  unsigned char ciphertext_as_hex[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE * 2];
  Read_Multiple_Lines_from_File(argv[2], ciphertext_as_hex, NUMBER_OF_MESSAGES);
  unsigned char ciphertext[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];
  Convert_To_Uchar((char *)ciphertext_as_hex, (unsigned char *)ciphertext, NUMBER_OF_MESSAGES * LENGTH_OF_EACH_MESSAGE);

  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned char prev_hash[SHA256_DIGEST_LENGTH]; // temp for previous digest
  unsigned char messages[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE+1];
  for (int i = 0; i < NUMBER_OF_MESSAGES; i++)
  {
    // compute hash of current shared_seed -> write into next_hash (avoid overlap)
    SHA256(shared_seed, shared_seed_len, hash);

    // decrypt directly from the binary ciphertext buffer
    AES256CTR_Decrypt(hash, ciphertext[i], LENGTH_OF_EACH_MESSAGE, messages[i]);
    messages[i][LENGTH_OF_EACH_MESSAGE] = '\0';
    printf("Plaintext %d == %s\n", i, messages[i]);

    // move next_hash into hash/shared_seed for the next iteration:
    memcpy(prev_hash, hash, SHA256_DIGEST_LENGTH);
    shared_seed = prev_hash;
    shared_seed_len = SHA256_DIGEST_LENGTH;
  }

  Write_Multiple_Lines_to_File("Plaintexts.txt", (char (*)[65])messages, NUMBER_OF_MESSAGES);

  return EXIT_SUCCESS;
}

/*************************************************************
					F u n c t i o n s
**************************************************************/
/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
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
  unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

/*=======================================
        Read Multiple Lines from File
========================================*/
//*** This function has a fixed output length (LENGTH_OF_EACH_MESSAGE) and takes the number of lines to read as an argument (ensure that array is of sufficient size)
//*** If necessary, change the output length accordingly (it can read lengths smaller than the specified size just fine)
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][LENGTH_OF_EACH_MESSAGE * 2], int num)
{
  char *line_buf = NULL;
  size_t line_buf_size = 0;
  int line_count = 0;
  ssize_t line_size;
  FILE *fp = fopen(fileName, "r");
  if (!fp)
      fprintf(stderr, "Error opening file '%s'\n", fileName);

  line_size = getline(&line_buf, &line_buf_size, fp);
  for(int j=0; line_size >= 0 && j < num; j++)
  {
    // Trim newline
    if (line_size > 0 && line_buf[line_size-1] == '\n')
        line_buf[--line_size] = '\0';

    memset(message[j], 0, LENGTH_OF_EACH_MESSAGE * 2);

    // Copy up to LENGTH_OF_EACH_MESSAGE or line_size, whichever is smaller
    int copy_len = line_size < (LENGTH_OF_EACH_MESSAGE * 2) ? line_size : (LENGTH_OF_EACH_MESSAGE * 2);
    memcpy(message[j], line_buf, copy_len);

    // Debug print, set print format length (*) to max LENGTH_OF_EACH_MESSAGE otherwise printf overruns with strings missing null terminator (which is most of the time) 
    printf("Message%d (%ld) == %.*s\n", j+1, line_size, LENGTH_OF_EACH_MESSAGE * 2, message[j]);

    line_size = getline(&line_buf, &line_buf_size, fp);
  }

  free(line_buf);
  fclose(fp);
}

/*============================================s
        Write Multiple Lines to File
==============================================*/
//*** This function has a fixed input length (LENGTH_OF_EACH_MESSAGE) and takes the number of lines to write as an argument
//*** If necessary, change the input size accordingly (for lines smaller than LENGTH_OF_EACH_MESSAGE, fputs relies on the null terminator to know where EOL is)
//*** If you want to write "unsigned char" into a file, change the format of 'input' and 'temp' to unsinged char (or just cast it on call)
void Write_Multiple_Lines_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE+1], int num) { 
    FILE *pFile;
    pFile = fopen(fileName,"w");
    if (pFile == NULL) {
        printf("Error opening file. \n");
        exit(0);
    }
    for(int i=0; i < num; i++) {
        char temp[LENGTH_OF_EACH_MESSAGE*2+1];
        temp[LENGTH_OF_EACH_MESSAGE*2] = '\0';
        memcpy(temp, input[i], LENGTH_OF_EACH_MESSAGE*2);
        fputs(temp, pFile);
        
        if (i < (num-1)) fputs("\n", pFile);
    }
    fclose(pFile);
}

/*============================
        Convert to Hex 
        Note: make sure output array size is double the size of input
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < inputlength; i++) {
        output[2 * i] = hex_digits[(input[i] >> 4) & 0x0F]; // high nibble
        output[2 * i + 1] = hex_digits[input[i] & 0x0F]; // low nibble
    }
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
        output[i] = (unsigned char)strtol(tmp, NULL, 16);
    }
}

/*==================================
    AES-256 CTR Encryption 
====================================*/
/*--- Description:
*   Function uses AES-256 (so 256-bit (32-byte) key)
*   Counter mode allows for any size input, with output same size as input
*   Explicitly set IV to keep the functions deterministic
*   Automatically pads input to block size
*/
void AES256CTR_Encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    unsigned char iv[16] = "1234567890uvwxyz";

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, output, &len, input, input_len);

    EVP_EncryptFinal_ex(ctx, output + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return;
}

void AES256CTR_Decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    unsigned char iv[16] = "1234567890uvwxyz";

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, output, &len, input, input_len);

    EVP_DecryptFinal_ex(ctx, output + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return;
}
//__________________________________________________________________________________________________________________________
