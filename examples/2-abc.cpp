#include <iostream>
#include <HashLib/sha256.hpp>

int main() {
    std::string msg = "abc";
    std::string correctHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha256_hash << "\nCHECK:  " << correctHash << "\n";

    return 0;
}