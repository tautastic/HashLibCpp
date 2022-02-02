#include <iostream>
#include <HashLib/sha224.hpp>

int main(int argc, char* argv[]) {
    std::string msg;
    for(int i = 1; i < argc; i++) {
        msg += (i > 1) ? (" " + std::string(argv[i])) : std::string(argv[i]);
    }
    auto sha224_hash = SHA2::SHA224::hash(msg);
    std::cout << "\n================SHA224================";
    std::cout << "\nInput: "  << msg;
    std::cout << "\nOutput: " << sha224_hash;
    std::cout << "\n================SHA224================\n\n";
    return 0;
}