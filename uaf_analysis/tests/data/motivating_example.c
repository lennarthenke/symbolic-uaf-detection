#include <stdio.h>
#include <stdlib.h>

void func(int a, int b) {
    int* ptr = (int*) malloc(sizeof(int)); // allocation
    int x = 1, y = 0;
    if (a != 0) {
        y = 3 + x;
        if (b == 0) {
            x = 2 * (a + b);
        }
    }
    free(ptr);  // deallocation
    if (x - y == 0) {
        *ptr = 42; // use-after-free
    }
}

int main() {
    int a, b;
    printf("Enter value for a: ");
    scanf("%d", &a);
    printf("Enter value for b: ");
    scanf("%d", &b);
    
    func(a, b);
    
    return 0;
}