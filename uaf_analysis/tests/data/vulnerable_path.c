#include <stdio.h>
#include <stdlib.h>

void safe_path1() {
    printf("Executing safe path 1.\n");
}

void safe_path2() {
    printf("Executing safe path 2.\n");
}

void vulnerable_path() {
    int *ptr = (int *) malloc(sizeof(int));
    *ptr = 42;
    printf("Value before free: %d\n", *ptr);
    free(ptr);

    // Use after free vulnerability
    printf("Value after free: %d\n", *ptr);
}

int main() {
    int input;
    printf("Enter a number (1-3): ");
    scanf("%d", &input);

    switch (input) {
        case 1:
            safe_path1();
            break;
        case 2:
            safe_path2();
            break;
        case 3:
            vulnerable_path();
            break;
        default:
            printf("Invalid input.\n");
    }

    return 0;
}
