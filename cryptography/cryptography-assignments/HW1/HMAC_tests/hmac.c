#include<stdio.h>
#include<string.h>
// openssl imports
#include<openssl/hmac.h>
#include<openssl/sha.h>
#include<openssl/evp.h>


//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
unsigned char* Hash_Blake2s(unsigned char* input, unsigned long inputlen);

int main(int argc, char *argv[]){
    int fileLenMessage = 0;    //initialize file length for message for Read_File function
    int fileLenKey = 0;    //initialize file length for key for Read_File function
    int inputlen = 0;   //initialize input length for Convert_to_Hex function

    //1. read message and shared secret key
    unsigned char *message = Read_File(argv[1], &fileLenMessage);    //initialize and read message text file
    unsigned char *key = Read_File(argv[2], &fileLenKey);    //initialize key and read shared key text file

    //2. convert key and write to file named Key.txt
    char hexkey[(fileLenKey * 2) + 1];    //allocate space for converted hex key, enough space as according to Convert_to_Hex function
    Convert_to_Hex(hexkey, key, fileLenKey);  //converts key to hex
    hexkey[fileLenKey * 2] = '\0';      //adds terminator character to end of line

    Write_File("Key.txt",hexkey); //write hexkey to Key.txt

    //3. The program processes the secret key so that it is exactly the block size of the hashing function
    unsigned char processedKey[64];     //block size in terms of bytes

    //if larger than block size, hash it
    if (fileLenKey > 64) {
        unsigned char *hashedKey = Hash_Blake2s(key, fileLenKey);   //initializes and stores the hash result size of 32

        memcpy(processedKey, hashedKey, 32);        //copies 32 bytes of the hashedKey variable into processedKey variable
        memset(processedKey + 32, 0, 64 - 32);      //fills processedKey with 0's, 32 bytes of them, from byte 32-63
        free(hashedKey);     //free memory from the hash function inside the variable
    } else {    //if not, pad with 0's till it is block size
        memcpy(processedKey, key, fileLenKey);        //similar to before, but takes key(copies however many 
                                                      // bytes are in key to processedKey) and length of key as the length of key is less than 32 bytes
        memset(processedKey + fileLenKey, 0, 64 - fileLenKey);      //fills processedKey with 0's, the amount of bytes filled depends on how long key was originally
    }

    //4. The program converts the processed key to Hex format and writes that in file named “ProcessedKey.txt”
    char processedHexKey[(64 * 2) + 1];    //allocate space for converted hex key after being processed, enough space as according to Convert_to_Hex function
    Convert_to_Hex(processedHexKey, processedKey, 64);  //converts processed key to hex
    processedHexKey[64 * 2] = '\0';      //adds terminator character to end of line of processed hex key
    
    Write_File("ProcessedKey.txt", processedHexKey); //write processedHexKey to ProcessedKey.txt
    
    //5. call the hmac function
    // create a storage space to store the hash and the result of HMAC
    unsigned char res[EVP_MAX_MD_SIZE];     //stores hash result
    unsigned int res_len=0;     //stores length of the hash result
    // hash the key and convert the key to hex
    // set the hash length to be digest length*2 +1 and the last char should be \0
    //changed to Hash_Blake2s from SHA
    HMAC(EVP_get_digestbyname("Blake2s256"), processedKey, 64, (unsigned char*) message, fileLenMessage, res, &res_len);       //use Blake2s instead of SHA to XOR the hash with the message
                                                    //processedKey is hashed to 64 bytes, message will be the input, fileLenMessage is the length of message, res is where the output of HMAC will be stored, and &res_len points to where the length of res will be stored
    
    //6. The program converts the HMAC to Hex format and writes it in a file named “FinalHash.txt”
    char finalHash[(64 * 2) + 1];    //allocate space for final hash after being converted, enough space as according to Convert_to_Hex function
    Convert_to_Hex(finalHash, res, res_len);  //converts final hash to hex
    finalHash[64 * 2] = '\0';      //adds terminator character to end of line of final hex key
    
    Write_File("FinalHash.txt", finalHash); //write processedHexKey to FinalHash.txt

    //free memory used up by variables
    free(message);
    free(key);

    return 0;
}


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
        Note: size of output storage best set to (inputlength * 2) + 1 to allow for null terminator by sprintf()
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
}

/*============================
        Blake 2s Hash Function
==============================*/

unsigned char* Hash_Blake2s(unsigned char* input, unsigned long inputlen) {
    unsigned char *hash_result = (unsigned char*) malloc(EVP_MAX_MD_SIZE); // malloc the EVP max size, which is 64, setting to 32 or 33 gives intermittent memory errors
    int hash_len; // ends up set to 32 during EVP_DigestFinal, unused
    
    const EVP_MD* md = EVP_get_digestbyname("BLAKE2s256"); // Get the BLAKE2s hashing (digest) algorithm
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); // Create the digest context required for next parts
    EVP_DigestInit_ex(mdctx, md, NULL); // Initialize the digest context for hashing with Blake2s
    EVP_DigestUpdate(mdctx, input, inputlen); // Update the digest context with the input to be hashed
    EVP_DigestFinal_ex(mdctx, hash_result, &hash_len); // Finalize the hash computation, putting result in hash_result

    EVP_MD_CTX_free(mdctx);

    return hash_result;
}