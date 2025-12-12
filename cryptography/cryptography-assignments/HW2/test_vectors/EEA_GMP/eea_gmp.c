#include <stdio.h>
#include <gmp.h>

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
char* ModularInverse(const unsigned char *number, const unsigned char *modulo);

int main(int argc, char* argv[])
{
  int numberLen, moduloLen;
  const unsigned char *number = Read_File (argv[1], &numberLen);
  const unsigned char *modulo = Read_File (argv[2], &moduloLen);

  char *modInv = ModularInverse(number, modulo);
  printf("Modular Inverse: %s\n", modInv);
  Write_File("Result.txt", modInv);
}

/*************************************************************
					F u n c t i o n s
**************************************************************/
/*============================
 * Extended Euclidean Algorithm
==============================*/
void ExtendedGCD(mpz_t gcd, mpz_t x, mpz_t y, mpz_t number, mpz_t modulo)
{
  if (mpz_sgn(modulo) == 0)
  {
    mpz_set(gcd, number);
    mpz_set_ui(x, 1);
    mpz_set_ui(y, 0);
    return;
  }

  mpz_t number_mod_modulo;
  mpz_t gcd1;
  mpz_t x1;
  mpz_t y1;
  mpz_t temp;
  mpz_t temp_neg;
  mpz_inits(number_mod_modulo, gcd1, x1, y1, temp, temp_neg, NULL);

  mpz_mod(number_mod_modulo, number, modulo);
  ExtendedGCD(gcd1, x1, y1, modulo, number_mod_modulo); 

  mpz_div(temp, number, modulo);
  mpz_mul(temp, temp, y1);
  mpz_neg(temp_neg, temp);
  mpz_add(temp, x1, temp_neg);

  mpz_set(gcd, gcd1);
  mpz_set(x, y1);
  mpz_set(y, temp);

  mpz_clears(number_mod_modulo, gcd1, x1, y1, temp, temp_neg, NULL);
}

/*============================
 * Modular Inverse as String
==============================*/
char* ModularInverse(const unsigned char *number_str, const unsigned char *modulo_str)
{
  mpz_t gcd;
  mpz_t x;
  mpz_t y;
  mpz_t number;
  mpz_t modulo;
  mpz_inits(gcd, x, y, number, modulo, NULL);
  
  mpz_set_str(number, (char *)number_str, 10);
  mpz_set_str(modulo, (char *)modulo_str, 10);

  ExtendedGCD(gcd, x, y, number, modulo);
  
  if (mpz_sgn(x) == -1)
    mpz_add(x, x, modulo);

  char* result_str = mpz_get_str(NULL, 10, x);
  mpz_clears(gcd, x, y, number, modulo, NULL);
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
