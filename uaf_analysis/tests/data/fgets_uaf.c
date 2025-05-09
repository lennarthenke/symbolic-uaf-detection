#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    char user_input[13];
    int* ptr;
    fgets(user_input, sizeof(user_input), stdin);
    ptr = (int*)malloc(20 * sizeof(int));
    free(ptr);
    if (strcmp("useAfterFree", user_input) == 0) {
        ptr[1] = 0xaBad1dea;
        return 0;
    }
}
