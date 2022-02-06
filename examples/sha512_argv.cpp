#include <iostream>
#include <HashLib/sha512.hpp>

int main(int argc, char* argv[]) {
    std::string msg;
    for(int i = 1; i < argc; i++) {
        msg += (i > 1) ? (" " + std::string(argv[i])) : std::string(argv[i]);
    }
    auto sha512_hash = SHA2::SHA512::hash(msg);
    std::cout << sha512_hash << "\n";
    return 0;
}