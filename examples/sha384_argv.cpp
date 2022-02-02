#include <iostream>
#include <HashLib/sha384.hpp>

int main(int argc, char* argv[]) {
    std::string msg;
    for(int i = 1; i < argc; i++) {
        msg += (i > 1) ? (" " + std::string(argv[i])) : std::string(argv[i]);
    }
    auto sha384_hash = SHA2::SHA384::hash(msg);
    std::cout << "\n================SHA384================";
    std::cout << "\nInput: "  << msg;
    std::cout << "\nOutput: " << sha384_hash;
    std::cout << "\n================SHA384================\n\n";
    return 0;
}