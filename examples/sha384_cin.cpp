#include <iostream>
#include <HashLib/sha384.hpp>

int main() {
    std::cout << "\n================SHA384================\nInput: ";
    std::string msg;
    std::cin >> msg;
    auto sha384_hash = SHA2::SHA384::hash(msg);
    std::cout << "OUTPUT: " << sha384_hash << "\n================SHA384================\n";

    return 0;
}