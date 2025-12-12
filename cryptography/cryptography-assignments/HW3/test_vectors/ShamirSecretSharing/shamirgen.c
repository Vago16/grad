#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h> // Required for PRId64 and PRIu64
#include <stdint.h> // for int64_t
#include <string.h> // for memcpy()
#include <unistd.h> // for ssize_t
#include <openssl/sha.h>    // for SHA256()
#include <openssl/evp.h> 

// number of shares generated in Shamir
#define N_SHARES 5
// minimum number of shares needed to reconstruct secret in Shamir
#define THRESHOLD 3

// Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
int64_t str_to_int64(const unsigned char *str, int str_len);
void int64_to_str(int64_t value, unsigned char *output, int output_len);
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out, size_t outlen);
int64_t evaluate_polynomial(int64_t coeffs[THRESHOLD], int64_t x, int64_t p);

int main(int argc, char *argv[])
{
  int secret_str_len;
  int modulus_str_len;
  unsigned char *secret_str = Read_File(argv[1], &secret_str_len);
  unsigned char *modulus_str = Read_File(argv[2], &modulus_str_len);

  int64_t secret = str_to_int64(secret_str, secret_str_len);
  int64_t modulus = str_to_int64(modulus_str, modulus_str_len);

  printf("modulus = %ld\n", modulus);

  // Step 1: generate random polynomial coefficients
  int64_t coefficients[THRESHOLD];
  coefficients[0] = secret;
  for (int i = 1; i < THRESHOLD; i++)
  {
    coefficients[i] = rand() % modulus;
    printf("coefficients[%d] = %ld\n", i, coefficients[i]);
  }

  // Step 2: compute shares
  int64_t y;
  char x_str[5]; 
  char y_str[30];
  char filename[20];
  char input[35];
  for (int64_t x = 1; x <= N_SHARES; x++)
  {
    y = evaluate_polynomial(coefficients, x, modulus);

    snprintf(x_str, sizeof(x_str), "%" PRId64, x);
    snprintf(y_str, sizeof(y_str), "%" PRId64, y);
    printf("Share %ld\n", x);
    printf("\tx = %s\n", x_str);
    printf("\ty = %s\n", y_str);

    sprintf(filename, "Share%s.txt", x_str);
    sprintf(input, "%s\n%s", x_str, y_str);

    Write_File(filename, input);
  }

  return EXIT_SUCCESS;
}

int64_t evaluate_polynomial(int64_t coeffs[THRESHOLD], int64_t x, int64_t p)
{
  int64_t y = 0;
  int64_t power_of_x = 1;
  for (int i = 0; i < THRESHOLD; i++)
  {
    // y = (y + coeffs[i] * power_of_x) % p;
    // power_of_x = (power_of_x * x) % p;
    y = (y + coeffs[i] * power_of_x) % p;
    if (y < 0) y += p;

    power_of_x = (power_of_x * x) % p;
    if (power_of_x < 0) power_of_x += p;
  }
  return y;
}

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

// Convert decimal string to int64_t
int64_t str_to_int64(const unsigned char *str, int str_len) {
    int64_t result = 0;
    int negative = 0;
    if (*str == '-') {
        negative = 1;
        str++;
    }
    for (int i=0; i < str_len && *str >= '0' && *str <= '9'; i++) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return negative ? -result : result;
}

// Convert int64_t to decimal string
// Note: ensure that output array size is large enough including the null terminator at the end
void int64_to_str(int64_t value, unsigned char *output, int output_len) {
    int negative = value < 0;
    if (negative) 
        value = -value;

    // Not going to need more than 10 digits, make it 15 just to be safe
    char temp[15];
    int i = 0;

    // In reverse order, reversed at the end
    do {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    } while (value > 0 && i < (int)sizeof(temp) - 1);

    if (negative) 
        temp[i++] = '-';

    if (i >= output_len) {
        output[0] = '\0';  // Not enough space
        return;
    }

    // Reverse the string into the output
    for (int j = 0; j < i; j++) {
        output[j] = temp[i - j - 1];
    }
    // Null-terminate
    output[i] = '\0';
}

/*==============================
        Concatenation Fucntion
================================*/
/*
    'in1' is a pointer to unsigned char array of length 'in1len', for the left part to be concatenated
    'in2' is a pointer to unsigned char array of length 'in2len', for the right part to be concatenated
    'out' is a pointer to unsigned char array of length 'outlen', for the place to put the concatenated result into
*/
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out, size_t outlen){
    if (in1len + in2len < outlen) {
        printf("Concatenation error: length of output is not enough to fit inputs. Behavior is undefined.\n");
    }
    memcpy(out, in1, in1len);
    memcpy(out+in1len, in2, in2len);
}
//__________________________________________________________________________________________________________________________
