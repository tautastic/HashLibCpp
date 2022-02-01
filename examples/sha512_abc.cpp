#include <iostream>
#include <HashLib/sha512.hpp>

int main() {
    std::string msg = "abc";
    std::string correctHash = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    auto sha512_hash = SHA2::SHA512::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha512_hash << "\nCHECK:  " << correctHash << "\n";

    return 0;
}