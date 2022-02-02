#include <iostream>
#include <HashLib/sha512.hpp>

int main() {
    std::string msg = "abc";
    auto sha512_hash = SHA2::SHA512::hash(msg);
    std::cout << "\n================SHA512================\nInput: " << msg;
    std::cout << "\nOUTPUT: " << sha512_hash << "\n================SHA512================\n";

    return 0;
}