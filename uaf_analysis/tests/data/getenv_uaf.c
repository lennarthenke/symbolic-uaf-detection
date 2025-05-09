#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void func(char **ptr) {
    char *tmp = getenv("SOME_ENV_VAR");
    if (tmp != NULL) {
        *ptr = strdup(tmp); // Allocate memory and duplicate the string
    }
}

int main() {
    char *env_var = NULL;
    func(&env_var);
    if (env_var != NULL) {
        printf("SOME_ENV_VAR: %s\n", env_var);
        free(env_var); // Free the allocated memory
    }
    // ... some other code ...
    printf("SOME_ENV_VAR (after free): %s\n", env_var); // Use-After-Free
    return 0;
}

