#include <iostream>
#include <HashLib/sha384.hpp>

int main() {
    std::string msg = "abc";
    auto sha384_hash = SHA2::SHA384::hash(msg);
    std::cout << "\n================SHA384================\nInput: " << msg;
    std::cout << "\nOUTPUT: " << sha384_hash << "\n================SHA384================\n";

    return 0;
}