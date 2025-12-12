#include <stdio.h>
#include <gmp.h>

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
char* SquareAndMultiply(const unsigned char *base_str, const unsigned char *exponent_str, const unsigned char *modulo_str);

int main(int argc, char* argv[])
{
  int baseLen, exponentLen, moduloLen;
  const unsigned char *base = Read_File (argv[1], &baseLen);
  const unsigned char *exponent = Read_File (argv[2], &exponentLen);
  const unsigned char *modulo = Read_File (argv[3], &moduloLen);

  char *snm = SquareAndMultiply(base, exponent, modulo);
  printf("Square-And-Multiply: %s\n", snm);
  Write_File("Result.txt", snm);

}

/*************************************************************
					F u n c t i o n s
**************************************************************/
/*============================
 * Square-And-Multiply Algorithm
==============================*/
char* SquareAndMultiply(const unsigned char *base_str, const unsigned char *exponent_str, const unsigned char *modulo_str)
{
  mpz_t base;
  mpz_t exponent;
  mpz_t modulo;
  mpz_t result;
  mpz_t two; 
  mpz_t b;
  mpz_t exponent_mod_two;
  mpz_inits(base, exponent, modulo, result, two, b, exponent_mod_two, NULL);
  
  mpz_set_str(base, (char *)base_str, 10);
  mpz_set_str(exponent, (char *)exponent_str, 10);
  mpz_set_str(modulo, (char *)modulo_str, 10);

  mpz_set_ui(result, 1);
  mpz_set_ui(two, 2);
  mpz_mod(b, base, modulo);

  while (mpz_sgn(exponent))
  {
    mpz_mod(exponent_mod_two, exponent, two);
    char *str10 = mpz_get_str(NULL, 10, exponent_mod_two);
    if (str10[0] == '1')
    {
      mpz_mul(result, result, b);
      mpz_mod(result, result, modulo);
    }

    mpz_mul(b, b, b);
    mpz_mod(b, b, modulo);
  
    mpz_div(exponent, exponent, two);
  }

  char* result_str = mpz_get_str(NULL, 10, result);
  mpz_clears(base, exponent, modulo, result, two, b, exponent_mod_two, NULL);
  return result_str;
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
