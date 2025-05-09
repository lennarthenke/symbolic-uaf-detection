#include <iostream>
#include <cstdlib>

int main() {
    int* ptr = new int;
    *ptr = 42;
    delete ptr;
    std::cout << "The value of ptr is " << *ptr << std::endl; // Use after free
    return 0;
}