#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

//Function prototypes
int gcd(int64_t a, int64_t b);

int main(int argc, char *argv[]) {
    //convert command line arguments to built-in int64 t data type
    int64_t a = strtoll(argv[1], NULL, 10);     //takes string to convert, pointer to first character not processed(irrelevant here), and the number base to convert to
    int64_t b = strtoll(argv[2], NULL, 10);

    //checking if coversion worked
    //printf("%ld\n", a);

    //apply euclidean algorithm gccd to two arguments
    int64_t res = gcd(a,b);

    //print result
    printf("%ld\n", res);

    return 0;
}

//gcd function, used int64_t type as specified
int gcd(int64_t a, int64_t b) {
    if (a == 0)     //gcd of 0 and another number is the other number 
        return b;
    return gcd(b % a, a);       //use modulo operationas according to Crash NumberTheoryIntro.pptx”, slide 7
}
