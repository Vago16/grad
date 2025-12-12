#include<stdio.h>
#include<stdlib.h>
#include<gmp.h>

int main(){
    
    printf("\n");
    printf("Size of int: %zu bytes, Max value: %d\n", sizeof(int), INT_MAX);
    printf("Size of long: %zu bytes, Max value: %ld\n", sizeof(long), LONG_MAX);
    printf("Size of long long: %zu bytes, Max value: %lld\n\n", sizeof(long long), LLONG_MAX);

    /* 
       - On most systems, 'int' is 4 bytes (32 bits) → can store up to about 2.1 billion (2^31 - 1).
       - 'long' may be 4 or 8 bytes depending on the compiler/system.
       - 'long long' is typically 8 bytes (64 bits) → can store up to about 9.22e18.
       These limits are fixed by hardware. Once we exceed them, we get overflow errors.
    */

    /*
        overflow demonstration
        using long long and finding factorials till 30
    */ 
   
    
    long long big =1;
    for (int i = 1; i <=30; i++){
        big *= i;
        printf("Factorial of %2d (approx with long long) = %lld\n",i,big);
    }

    /*
        after 20, the values are all wrong
    */ 

    printf("\n");

    mpz_t factorial;
    mpz_init(factorial);
    mpz_set_ui(factorial, 1);

    for(int i =1; i <= 100; i++){
        mpz_mul_ui(factorial, factorial, i);  // factorial *= i
    }

    /*
        this won't work :(
    */ 

    printf("100! = %d \n\n", factorial);
    
    /*
        GMP has it's own print function :)
    */

    gmp_printf("100! = %Zd \n\n", factorial);

    return 0;
}