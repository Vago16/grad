#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

int main(int argc, char* argv[]){
    mpz_t a,b, product;
    mpz_inits(a,b,product, NULL);
    mpz_set_str(a, argv[1], 10);
    mpz_set_str(b, argv[2], 10);
    mpz_mul(product, a, b);
    gmp_printf("a x b = %Zd\n", product);
    return 0;
}