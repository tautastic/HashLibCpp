#include <iostream>
#include <HashLib/sha256.hpp>

int main(int argc, char* argv[]) {
    std::string msg;
    for(int i = 1; i < argc; i++) {
        msg += (i > 1) ? (" " + std::string(argv[i])) : std::string(argv[i]);
    }
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "\n================SHA256================";
    std::cout << "\nInput: "  << msg;
    std::cout << "\nOutput: " << sha256_hash;
    std::cout << "\n================SHA256================\n\n";
    return 0;
}