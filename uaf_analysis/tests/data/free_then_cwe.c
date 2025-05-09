#include <stdio.h>
#include <stdlib.h>

struct my_struct {
    int x;
    int y;
};

void my_function(struct my_struct* obj, int do_free) {
    if (obj != NULL && obj->x == 42) {
        if (do_free) {
            free(obj);
            printf("Object freed\n");
        } else {
            printf("Object not freed\n");
        }
    } else {
        printf("Object not valid\n");
    }
}

int main() {
    struct my_struct* obj = (struct my_struct*) malloc(sizeof(struct my_struct));
    obj->x = 42;
    obj->y = 10;
    printf("Object allocated\n");
    
    my_function(obj, 0);
    
    // Trying to access the object after it has been freed
    my_function(obj, 1);
    printf("Object after free: x=%d, y=%d\n", obj->x, obj->y);
    
    return 0;
}
