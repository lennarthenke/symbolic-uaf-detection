#include <stdio.h>
#include <stdlib.h>

int main() {
    int* arr = (int*)reallocarray(NULL, 5, sizeof(int));  // allocate memory for 5 integers
    free(arr);  // free the allocated memory
    arr[0] = 42;  // Use After Free vulnerability
    printf("The value of arr[0] is %d\n", arr[0]);
    return 0;
}
