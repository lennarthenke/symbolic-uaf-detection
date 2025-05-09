#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char* str;
    printf("Enter a string: ");
    scanf("%ms", &str); // Note: %ms will allocate memory dynamically
    
    int len = strlen(str);
    printf("The length of the string is %d\n", len);
    
    free(str);
    printf("Memory freed\n");
    
    // Trying to access the freed memory location
    printf("The string is: %s\n", str);
    
    return 0;
}
