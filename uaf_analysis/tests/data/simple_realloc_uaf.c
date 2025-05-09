#include <stdlib.h>
#include <stdio.h>

int main() {
    int *ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    int *ptr2 = (int*)realloc(ptr, 0);
    printf("The value of ptr is %d\n", *ptr); // Use after free
    return 0;
}