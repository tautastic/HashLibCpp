# HashLibCpp


| Branch |                                                                                 CMake                                                                                 |                                                                  CircleCi                                                                   |
|:------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------------------------:|
| master |      [![CMake](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml/badge.svg)](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml)       | [![CircleCI](https://circleci.com/gh/ADD1609/HashLibCpp/tree/master.svg?style=svg)](https://circleci.com/gh/ADD1609/HashLibCpp/tree/master) |
|  dev   | [![CMake](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml/badge.svg?branch=dev)](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml) |  [![CircleCI](https://circleci.com/gh/ADD1609/HashLibCpp/tree/dev.svg?style=svg)](https://circleci.com/gh/ADD1609/HashLibCpp/tree/master)   |




## Features
### SHA256:
```c++
// main.cpp
#include <iostream>
#include <HashLib/sha256.hpp>

int main() {
    std::string msg = "Hello World";
    auto sha256_hash = SHA2::SHA256::hash(msg);
    std::cout << "\nInput:  " << msg << "\nSHA256: " << sha256_hash;

    return 0;
}
```
### Output:
```commandline
Input:  Hello World
SHA256: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
Process finished with exit code 0
```