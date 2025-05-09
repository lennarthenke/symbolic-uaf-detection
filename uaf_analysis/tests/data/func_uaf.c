#include <stdlib.h>
#include <stdio.h>

void allocate(int** ptr) {
    *ptr = (int*)malloc(sizeof(int));
    **ptr = 42;
}

void free_mem(int** ptr) {
    free(*ptr);
}

void use_after_free(int* ptr) {
    printf("The value of ptr is %d\n", *ptr); // Use After Free vulnerability
}

int main() {
    int* ptr;
    allocate(&ptr);
    free_mem(&ptr);
    use_after_free(ptr);
    return 0;
}
