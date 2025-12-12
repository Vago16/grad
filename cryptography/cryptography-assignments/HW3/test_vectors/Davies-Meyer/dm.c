#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

// Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void AES128ECB_Encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output);


int main(int argc, char *argv[]) {
    //parameters of the text file to be read
    const char *text_name = argv[1];
    int message_len = 0;

    unsigned char *message = Read_File(text_name, &message_len);    //read the message.txt file and store in message address space

    int blocks = (message_len + 15) / 16; //divides into 16 byte blocks
    
    if (blocks == 0) {  //if empty message, create one block to allow hash to work
        blocks = 1;
    }

    int padding_length = blocks * 16;      //initializes length variable to pad the byte counts
    unsigned char *padding = (unsigned char*) calloc(padding_length, 1);      //fills buffer with zeroes
    memcpy(padding, message, message_len);          //copies message into padding with any remaining of the 16 bytes being 0's if not filled

    unsigned char previous_hash[16];        //initialize previous hash(Hashi−1))
    memset(previous_hash, 0x00, 16);        //initilaize first previous hash's 16 bytes as all 0's    

    unsigned char c_text[16];       //initialize ciphertext results gotten from AES
    unsigned char hash_res[16];     //initialize computed hash i
    char hex_res[16 * 2 + 1];       // 32 hex characters puls terminating character

    //for loop to iterate through each block
    for (int i = 0; i < blocks; i++) {
        unsigned char *block = padding + (i * 16);

        //use AES128-ECB hash to encrypt with the previous_hash as the key and compress the blocks(plaintext) and put the result into c_text
        AES128ECB_Encrypt(block, previous_hash, c_text);

        //Hashi = AES(M sgi, Hashi−1) ⊕ Hashi−1 portion of the Davies-Meyer function to XOR, for every byte iterate
        for (int j = 0; j < 16; j++) {
            hash_res[j] = c_text[j] ^ previous_hash[j]; //XOR each byte with previous
        }

        //if this is the first hash being processed
        if (i == 0) {
            Convert_to_Hex(hex_res, hash_res, 16);  //convert hash to hex of size 16 bytes
            Write_File("FirstHash.txt", hex_res);   //write first hex result to txt file
        }


        //if this is the final hash being processed
        if (i == (blocks - 1)) {
            Convert_to_Hex(hex_res, hash_res, 16);  //convert hash to hex of size 16 bytes
            Write_File("FinalHash.txt", hex_res);   //write final hex result to txt file
        }

        memcpy(previous_hash, hash_res, 16);    //makes the current hash into the previous hash for the next iteration
    }

    //free memory
    free(message);
    free(padding);

    return 0;
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

/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex (char name[], unsigned char input[], int inputlen)
{
	printf("%s %d: ", name, inputlen);
	for (int i = 0 ; i < inputlen ; i++)
   		printf("%02x", input[i]);
	printf("\n");
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

/*==================================
    AES-128 ECB Encryption Function
====================================*/
/*--- Description:
*   Function uses AES-128 (so 128-bit input, 128-bit output, and 128-bit key)
*       ECB, so no chaining or IV, sufficient for a toy implementation
*       Explicitly set no padding, so input must be 16 bytes exactly
*/
void AES128ECB_Encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;

    EVP_EncryptInit_ex2(ctx, EVP_aes_128_ecb(), key, NULL, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // Disable padding

    EVP_EncryptUpdate(ctx, output, &outlen, input, 16);

    EVP_CIPHER_CTX_free(ctx);
}

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[]) {
    FILE *pFile;
    pFile = fopen(fileName,"w");
    if (pFile == NULL){
        printf("Error opening file. \n");
        exit(0);
    }
    fputs(input, pFile);
    fclose(pFile);
}

