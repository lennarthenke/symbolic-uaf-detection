#include <stdlib.h>
#include <stdio.h>

void bug() {
    int *ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    printf("\n%d\n", *ptr);
    free(ptr);
    printf("\n%d\n", *ptr);
    return;
}

int main() {
    char input[100];
    int counter = 0, values = 0;
    fgets(input, sizeof(input), stdin);
    for (int i = 0; i < 100; i++) {
        if (input[i] == 'B') {
            counter++;
            values += 2;
        }
    }
    printf("counter: %d values: %d\n", counter, values);
    if (counter == 75) {
        bug();
    }
}
