#include <iostream>
#include <HashLib/sha384.hpp>

int main() {
    std::string msg = "abc";
    auto sha384_hash = SHA2::SHA384::hash(msg);
    std::cout << "INPUT:  " << msg << "\nOUTPUT: " << sha384_hash << "\n";

    return 0;
}