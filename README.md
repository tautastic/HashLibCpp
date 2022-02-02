# HashLibCpp
This repository aims to provide an easy-to-use implementation of the Secure Hash Standard. (currently implemented are SHA224, SHA256 and SHA512)

All functions are implemented as specified in [NIST-FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

Feel free to fork, contribute to, use or open issues in, this repository. Since I am neither a C++ nor a cryptography professional, suggestions and or help is appreciated.

## Status

|   Branch   |                                                                                           master                                                                                            |                                                                                                  dev                                                                                                   |
|:----------:|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|   CMake    |                 [![CMake](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml/badge.svg)](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml)                  |                 [![CMake](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml/badge.svg?branch=dev)](https://github.com/ADD1609/HashLibCpp/actions/workflows/cmake.yml)                  |
|  CircleCi  |                         [![CircleCI](https://circleci.com/gh/ADD1609/HashLibCpp/tree/master.svg?style=svg)](https://circleci.com/gh/ADD1609/HashLibCpp/tree/master)                         |                                 [![CircleCI](https://circleci.com/gh/ADD1609/HashLibCpp/tree/dev.svg?style=svg)](https://circleci.com/gh/ADD1609/HashLibCpp/tree/dev)                                  |
| Flawfinder | [![flawfinder](https://github.com/ADD1609/HashLibCpp/actions/workflows/flawfinder-analysis.yml/badge.svg)](https://github.com/ADD1609/HashLibCpp/actions/workflows/flawfinder-analysis.yml) | [![flawfinder](https://github.com/ADD1609/HashLibCpp/actions/workflows/flawfinder-analysis.yml/badge.svg?branch=dev)](https://github.com/ADD1609/HashLibCpp/actions/workflows/flawfinder-analysis.yml) |

## Disclaimer
**I am neither a C++ nor a cryptography professional, thus my implementation of the Secure Hash Standard should not be used in production code.**

## Example
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