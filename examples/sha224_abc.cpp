#include <iostream>
#include <HashLib/sha224.hpp>

int main() {
    std::string msg = "abc";
    auto sha224_hash = SHA2::SHA224::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha224_hash << "\n";

    return 0;
}