#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Please provide an argument\n");
        return 1;
    }

    int len = strlen(argv[1]);
    char* str = (char*) malloc(sizeof(char) * (len + 1));
    strcpy(str, argv[1]);
    printf("The string you entered is: %s\n", str);

    // Freeing the allocated memory
    free(str);
    printf("Memory freed\n");

    // Using the memory after it has been freed to print the last character of the string
    printf("The last character of the string after free is: %c\n", *(str + len - 1));

    return 0;
}
