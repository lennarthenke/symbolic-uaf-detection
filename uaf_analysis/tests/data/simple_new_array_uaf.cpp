#include <iostream>

int main() {
    int n = 5;
    int* arr = new int[n];
    for (int i = 0; i < n; i++) {
        arr[i] = i;
        std::cout << arr[i] << " ";
    }
    
    delete[] arr;
    std::cout << "\nMemory freed\n";
    
    // Trying to access the freed memory location
    std::cout << "The array is: ";
    for (int i = 0; i < n; i++) {
        std::cout << arr[i] << " ";
    }
    std::cout << "\n";
    
    return 0;
}
