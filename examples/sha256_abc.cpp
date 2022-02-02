#include <iostream>
#include <HashLib/sha256.hpp>

int main() {
    std::string msg = "abc";
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "\n================SHA256================\nInput: " << msg;
    std::cout << "\nOUTPUT: " << sha256_hash << "\n================SHA256================\n";

    return 0;
}