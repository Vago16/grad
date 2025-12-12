#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // for int64_t
#include <string.h> // for memcpy()
#include <unistd.h> // for ssize_t
#include <openssl/sha.h>    // for SHA256()
#include <openssl/evp.h> 

// number of shares generated in Shamir
#define N_SHARES 5
// minimum number of shares needed to reconstruct secret in Shamir
#define THRESHOLD 3

// Structure definitions
typedef struct{
  int64_t gcd;
  int64_t x;
  int64_t y;
} EGCD;

typedef struct{
  int64_t x;
  int64_t y;
} SHARE;

// Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][30], int num);
void Write_File(char fileName[], char input[]);
int64_t str_to_int64(const unsigned char *str, int str_len);
void int64_to_str(int64_t value, unsigned char *output, int output_len);
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out, size_t outlen);
int64_t ModularInverse(int64_t number, int64_t modulo);
int64_t lagrange_interpolation_at_zero(SHARE *shares, int64_t p);

int main(int argc, char *argv[])
{
  int modulus_str_len;
  unsigned char *modulus_str = Read_File(argv[1], &modulus_str_len);
  int64_t modulus = str_to_int64(modulus_str, modulus_str_len);

  SHARE *shares = malloc(sizeof(SHARE)*N_SHARES);

  char x_str[5]; 
  char filename[20];
  unsigned char share[2][30];
  for (int x = 1; x <= N_SHARES; x++)
  {
    snprintf(x_str, sizeof(x_str), "%d", x);
    sprintf(filename, "Share%s.txt", x_str);

    Read_Multiple_Lines_from_File(filename, share, 30);

    shares[x-1].x = str_to_int64(share[0], 30);
    shares[x-1].y = str_to_int64(share[1], 30);
  }

  for (int i = 0; i < N_SHARES; i++)
  {
    printf("Share %d:\n", i+1);
    printf("\tx: %ld\n", shares[i].x);
    printf("\ty: %ld\n", shares[i].y);
  }

  int64_t secret = lagrange_interpolation_at_zero(shares, modulus);
  unsigned char secret_str[30];
  int64_to_str(secret, secret_str, sizeof(secret_str));
  
  printf("secret: %s\n", secret_str);
  Write_File("Recovered.txt", (char *)secret_str);

  return EXIT_SUCCESS;
}
uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t p) {
    uint64_t result = 0;
    a = a % p;
    while (b > 0) {
        if (b & 1)
            result = (result + a) % p;
        a = (a * 2) % p;
        b >>= 1;
    }
    return result;
}
int64_t lagrange_interpolation_at_zero(SHARE *shares, int64_t p) {
    int64_t secret = 0;

    for (int j = 0; j < THRESHOLD; j++) {
        int64_t numerator = 1;
        int64_t denominator = 1;

        for (int m = 0; m < THRESHOLD; m++) {
            if (m == j) continue;

            // numerator = numerator * (-x_m) mod p
            int64_t num_term = ((-shares[m].x) % p + p) % p;
            numerator = mod_mul((uint16_t)numerator, (uint16_t)num_term, (uint16_t)p);

            // denominator = denominator * (x_j - x_m) mod p
            int64_t denom_term = ((shares[j].x - shares[m].x + p) % p);
            denominator = mod_mul(denominator, denom_term, p);
        }

        int64_t denom_inv = ModularInverse(denominator, p);
        int64_t Lj = mod_mul(numerator, denom_inv, p);

        secret = (secret + shares[j].y * Lj) % p;
    }

    return secret;
}

/*============================
 * Extended Euclidean Algorithm
==============================*/
EGCD ExtendedGCD(int64_t number, int64_t modulo)
{

  if (modulo == 0)
  {
    EGCD egcd;
    egcd.gcd = number;
    egcd.x = 1;
    egcd.y = 0;
    return egcd;
  }

  EGCD egcd1 = ExtendedGCD(modulo, (number % modulo)); 

  int64_t temp = egcd1.x - (number / modulo) * egcd1.y;

  EGCD egcd;
  egcd.gcd = egcd1.gcd;
  egcd.x = egcd1.y;
  egcd.y = temp;
  return egcd;
}

/*============================
 * Modular Inverse as String
==============================*/
int64_t ModularInverse(int64_t number, int64_t modulo)
{
  EGCD egcd = ExtendedGCD(number, modulo);

  if (egcd.gcd != 1)
    return -1;
  
  int64_t result = egcd.x;
  if (result < 0)
    result+=modulo;

  return result;
}

/*=======================================
        Read Multiple Lines from File
========================================*/
//*** This function has a fixed output length (30) and takes the number of lines to read as an argument (ensure that array is of sufficient size)
//*** If necessary, change the output length accordingly (it can read lengths smaller than the specified size just fine)
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][30], int num)
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

        memset(message[j], 0, 30);

        // Copy up to 30 or line_size, whichever is smaller
        int copy_len = line_size < 30 ? line_size : 30;
        memcpy(message[j], line_buf, copy_len);

        line_size = getline(&line_buf, &line_buf_size, fp);
    }

    free(line_buf);
    fclose(fp);
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
