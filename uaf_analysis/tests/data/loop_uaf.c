#include <stdlib.h>
#include <stdio.h>

int main() {
    int* ptr;
    for (int i = 0; i < 10; i++) {
        ptr = (int*)malloc(sizeof(int));
        *ptr = i;
        free(ptr);
    }
    printf("The value of ptr is %d\n", *ptr); // Use after free
    return 0;
}