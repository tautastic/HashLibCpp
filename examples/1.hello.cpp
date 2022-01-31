#include <iostream>
#include <HashLib/sha256.hpp>

int main() {
    std::string msg = "Hello World";
    std::string correctHash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha256_hash << "\nCHECK:  " << correctHash;

    return 0;
}