#include <iostream>
#include <HashLib/sha256.hpp>

int main() {
    std::cout << "\n================SHA256================\nInput: ";
    std::string msg;
    std::cin >> msg;
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "OUTPUT: " << sha256_hash << "\n================SHA256================\n";

    return 0;
}