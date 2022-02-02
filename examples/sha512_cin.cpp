#include <iostream>
#include <HashLib/sha512.hpp>

int main() {
    std::cout << "\n================SHA512================\nInput: ";
    std::string msg;
    std::cin >> msg;
    auto sha512_hash = SHA2::SHA512::hash(msg);
    std::cout << "OUTPUT: " << sha512_hash << "\n================SHA512================\n";

    return 0;
}