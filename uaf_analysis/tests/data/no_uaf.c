#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    char *data;
    int random_number;
    data = NULL;
    data = (char *)malloc(100 * sizeof(char));
    if (data == NULL) {
        exit(-1);
    }
    memset(data, 'A', 99);
    data[99] = '\0';
    srand(time(NULL));
    random_number = rand() % 100 + 1;
    if (random_number == 1) {
        free(data);
    } else if (random_number < 50) {
        free(data);
    } else if (random_number == 100) {
        free(data);
    } else {
        printf("%s\n", data);
        free(data);
    }
    return 0;
}