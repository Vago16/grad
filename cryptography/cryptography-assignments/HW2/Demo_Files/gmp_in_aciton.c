#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

int main() {
    /*************************************************************
        1. GMP Integer Initialization
    **************************************************************/

    // Assign values to variables
    // from string to mpz_int
    char *a_str = "64589732645982736459827364598276598726598726598567898765434567897654";
    char *b_str = "64589732645982736459827364598276598726598726598";
    
    mpz_t a_int;
    mpz_t b_int;
    mpz_inits(a_int, b_int, NULL);
    
    mpz_set_str(a_int, a_str, 10);
    mpz_set_str(b_int, b_str, 10);
    
    gmp_printf("\nInitial values: \na = %Zd, \nb = %Zd\n\n", a_int, b_int);
    
    // Copy value: d = c
    mpz_t c_int;
    mpz_init(c_int);
    mpz_set(c_int, b_int);

    gmp_printf("Copied value: \nc = %Zd\n\n", b_int);
    
    /*************************************************************
     3. Arithmetic Operations
     **************************************************************/
    
    mpz_t sum, difference, product, mod, quotient;
    
    mpz_inits(sum, difference, product, mod, quotient, NULL);
    
    // Addition: sum = a + b
    mpz_add(sum, a_int, b_int);
    gmp_printf("Sum (a + b) = %Zd\n", sum);
    
    // Subtraction: diff = a-b
    // Convert b to -ve
    mpz_t b_neg;
    mpz_init(b_neg);
    mpz_neg(b_neg,b_int);
    gmp_printf("-b = %Zd\n", b_neg);
    mpz_add(difference, a_int, b_neg);
    gmp_printf("Difference (a-b) = %Zd\n", difference);

    // Multiplication: product = a * b
    mpz_mul(product, a_int, b_int);
    gmp_printf("Product (a * b) = %Zd\n", product);
    
    // Modulo: mod = a mod p
    mpz_t p_int;
    mpz_init(p_int);
    mpz_set_ui(p_int, 13);
    mpz_mod(mod, a_int, p_int);
    gmp_printf("Modulo (a mod %Zd) = %Zd\n", p_int, mod);

    // Division: quotient = c / b
    mpz_fdiv_q(quotient, a_int, b_int);
    gmp_printf("Quotient (a / b) = %Zd\n\n", quotient);

    /*************************************************************
        4. Comparison Example
    **************************************************************/
    mpz_t i_int;
    mpz_init(i_int);
    mpz_set_si(i_int, -45678);
    int cmp = mpz_sgn(i_int); // returns +1 if positive, 0 if zero, -1 if negative
    printf("Sign of i: %d \n(1 = positive, 0 = zero, -1 = negative)\n\n", cmp);

    /*************************************************************
        5. Output in Different Bases
    **************************************************************/
    mpz_t d_int;
    mpz_init(d_int);
    mpz_set_ui(d_int,15);
    char *str10 = mpz_get_str(NULL, 10, d_int); // decimal string
    char *str16 = mpz_get_str(NULL, 16, d_int); // hexadecimal string
    char *str2  = mpz_get_str(NULL, 2,  d_int); // binary string

    printf("c in base 10: %s\n", str10);
    printf("c in base 16: %s\n", str16);
    printf("c in base 2 : %s\n\n", str2);

    // free memory allocated by mpz_get_str (malloc inside GMP)
    free(str10);
    free(str16);
    free(str2);

    // /*************************************************************
    //     6. Clearing Memory
    // **************************************************************/
    mpz_clear(a_int);
    mpz_clears(b_int, b_neg, c_int, d_int, i_int, p_int, sum, product, mod, quotient, NULL);

    return 0;
}