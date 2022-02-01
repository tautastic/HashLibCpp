#include <iostream>
#include <HashLib/sha512.hpp>

int main() {
    std::string msg = "abc";
    auto sha512_hash = SHA2::SHA512::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha512_hash << "\n";

    return 0;
}