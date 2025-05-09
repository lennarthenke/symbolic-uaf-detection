#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

void* allocate_free_loop(void* arg) {
    int* ptr;
    for (int i = 0; i < 10; i++) {
        ptr = (int*)malloc(sizeof(int));
        *ptr = i;
        free(ptr);
    }
    return NULL;
}

int main() {
    pthread_t thread1, thread2;
    pthread_create(&thread1, NULL, allocate_free_loop, NULL);
    pthread_create(&thread2, NULL, allocate_free_loop, NULL);
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    int* ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    printf("The value of ptr is %d\n", *ptr); // Use after free
    return 0;
}