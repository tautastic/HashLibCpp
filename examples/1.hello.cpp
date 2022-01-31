#include <iostream>
#include <HashLib/sha256.hpp>

int main() {
    std::string msg = "Hello World";
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "\nInput:  " << msg << "\nSHA256: " << sha256_hash << "\n";

    return 0;
}