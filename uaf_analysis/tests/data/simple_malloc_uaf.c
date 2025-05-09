#include <stdlib.h>
#include <stdio.h>

int main() {
    int *ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    printf("The value of ptr is %d\n", *ptr); // Use after free
    return 0;
}