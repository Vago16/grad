#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 128-bit integer type, typedef'd for better readability
typedef __int128 int128_t;

// Structure definitions
typedef struct{
  int128_t x;
  int128_t a;
  int128_t b;
} Step;

typedef struct{
  int128_t gcd;
  int128_t x;
  int128_t y;
} EGCD;

// Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
int128_t str_to_int128(const unsigned char *str, int str_len);
void int128_to_str(int128_t value, unsigned char *output, int output_len);
int128_t GCD(int128_t a, int128_t b); 
int128_t SquareAndMultiply(int128_t base, int128_t exponent, int128_t modulo);
int128_t ModularInverse(int128_t number, int128_t modulo);
int128_t PollardRho(int128_t alpha, int128_t Y, int128_t p);
 
int main(int argc, char* argv[])
{
  // Seed the random number generator once
  srand(time(NULL));

  int alphaLen, YLen, pLen;
  const unsigned char *alpha_str = Read_File (argv[1], &alphaLen);
  const unsigned char *Y_str = Read_File (argv[2], &YLen);
  const unsigned char *p_str = Read_File (argv[3], &pLen);

  printf("Alpha: %s\nY: %s\np: %s\n\n", alpha_str, Y_str, p_str);

  int128_t result = PollardRho(
    str_to_int128(alpha_str, alphaLen),
    str_to_int128(Y_str, YLen),
    str_to_int128(p_str, pLen)
  );

  unsigned char result_str[50];
  int result_len = sizeof(result_str);
  int128_to_str(result, result_str, result_len);

  printf("Result: %s\n", result_str);
  Write_File("Exponent.txt", (char *)result_str);
}

/*************************************************************
					F u n c t i o n s
**************************************************************/
/*============================
 * Random 128 bit integers
==============================*/
int128_t rand_int128(int128_t q)
{
  int128_t r;
  do {
    unsigned long high = ((unsigned long)rand() << 32) | rand();
    unsigned long low = ((unsigned long)rand() << 32) | rand();
    r = ((int128_t)high << 64) | low;
  } while (r >= q);
  return r;
}

/*============================
 * 
==============================*/
Step f_step(int128_t x, int128_t a, int128_t b, int128_t alpha, int128_t Y, int128_t p, int128_t q)
{
  int128_t part = x % 3; // partition function
  Step new_step;
  if (part == 0)
  {
    // multiply by alpha
    new_step.x = (x * alpha) % p;
    new_step.a = (a + 1) % q;
    new_step.b = b;
  }
  else if (part == 1)
  {
    // square
    new_step.x = (x * x) % p;
    new_step.a = (2 * a) % q;
    new_step.b = (2 * b) % q;
  }
  else{
    // multiply by Y
    new_step.x = (x * Y) % p;
    new_step.a = a;
    new_step.b = (b + 1) % q;
  }
  return new_step;
}

/*============================
 * 
==============================*/
int128_t PollardRho(int128_t alpha, int128_t Y, int128_t p)
{
  int128_t q = p - 1;

  while (1)
  {
    int128_t a0 = rand() % q;
    int128_t b0 = rand() % q;

    int128_t x = (SquareAndMultiply(alpha, a0, p) * SquareAndMultiply(Y, b0, p)) % p;
    int128_t a = a0;
    int128_t b = b0;

    int128_t X = x;
    int128_t A = a;
    int128_t B = b;

    // Floyd cycle-finding loop
    while (1)
    {
      // tortoise: one step
      Step tortoise_step = f_step(x, a, b, alpha, Y, p, q);
      x = tortoise_step.x;
      a = tortoise_step.a;
      b = tortoise_step.b;

      // hare: two steps
      Step hare_step = f_step(X, A, B, alpha, Y, p, q);
      hare_step = f_step(hare_step.x, hare_step.a, hare_step.b, alpha, Y, p, q);
      X = hare_step.x;
      A = hare_step.a;
      B = hare_step.b;

      if (x == X)
      {
        // collision found: alpha^a * Y^b == alpha^A * Y^B (mod p)
        if (a == A && b == B)
          // trivial collision due to same state; restart 
          break; // break while True; go to next attempt

        int128_t lhs = (b - B) % q;
        int128_t rhs = (A - a) % q;

        int128_t g = GCD(lhs, q);

        if (g == 0)
          // highly unlikely; restart
          break; // break while True; go to next attempt
          
        if (g == 1)
        {
          int128_t inv_lhs = ModularInverse(lhs, q);
          if (inv_lhs == -1)
            break;

          int128_t x_solution = (rhs * inv_lhs) % q;
          if (SquareAndMultiply(alpha, x_solution, p) == (Y % p))
            return x_solution;
          else
            break;
        }
        else
        {
          if (rhs % g != 0)
            break;

          int128_t lhs_reduced = (lhs / g) % (q / g);
          int128_t rhs_reduced = (rhs / g) % (q / g);
          int128_t inv_reduced = ModularInverse(lhs_reduced, (q / g));
          if (inv_reduced == -1)
            break;

          int128_t x0 = (rhs_reduced * inv_reduced) % (q / g);

          for (int k = 0; k < g; k++)
          {
            int128_t candidate = (x0 + k * (q / g)) % q;
            if (SquareAndMultiply(alpha, candidate, p) == (Y % p))
              return candidate;
          }

          break;
        }
      }
    }
  }
}

/*============================
 * Extended Euclidean Algorithm
==============================*/
EGCD ExtendedGCD(int128_t number, int128_t modulo)
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

  int128_t temp = egcd1.x - (number / modulo) * egcd1.y;

  EGCD egcd;
  egcd.gcd = egcd1.gcd;
  egcd.x = egcd1.y;
  egcd.y = temp;
  return egcd;
}

/*============================
 * Modular Inverse as String
==============================*/
int128_t ModularInverse(int128_t number, int128_t modulo)
{
  EGCD egcd = ExtendedGCD(number, modulo);

  if (egcd.gcd != 1)
    return -1;
  
  int128_t result = egcd.x;
  if (result < 0)
    result+=modulo;

  unsigned char result_str[50];
  int result_len = sizeof(result_str);
  int128_to_str(result, result_str, result_len);
  printf("modInv: %s\n", result_str);

  return result;
}

/*============================
 * Square-And-Multiply Algorithm
==============================*/
int128_t SquareAndMultiply(int128_t base, int128_t exponent, int128_t modulo)
{
  int128_t result = 1;
  int128_t b = base % modulo;

  while (exponent > 0)
  {
    if ((exponent % 2) == 1)
      result = (result * b) % modulo;

    b = (b * b) % modulo;
    exponent = exponent / 2;
  }

  return result;
}

/*============================
        GCD
==============================*/
int128_t GCD(int128_t a, int128_t b) {
    if (a < 0) a = -a; // optional: ensure positive
    if (b < 0) b = -b;

    while (b != 0) {
        int128_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
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

/*************************************************************
                    int128_t Functions
**************************************************************/
// Convert decimal string to int128_t
int128_t str_to_int128(const unsigned char *str, int str_len) {
    int128_t result = 0;
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

// Convert int128_t to decimal string
void int128_to_str(int128_t value, unsigned char *output, int output_len) {
    int negative = value < 0;
    if (negative) 
        value = -value;

    // Not going to need more than 40 digits, make it 50 just to be safe
    char temp[50];
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
//__________________________________________________________________________________________________________________________
