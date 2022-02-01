#include <iostream>
#include <HashLib/sha224.hpp>

int main() {
    std::string msg = "abc";
    std::string correctHash = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
    auto sha224_hash = SHA2::SHA224::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha224_hash << "\nCHECK:  " << correctHash << "\n";

    return 0;
}