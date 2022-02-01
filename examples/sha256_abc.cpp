#include <iostream>
#include <HashLib/sha256.hpp>

int main() {
    std::string msg = "abc";
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha256_hash << "\n";

    return 0;
}