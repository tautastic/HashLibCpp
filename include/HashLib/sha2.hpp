#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <string>

namespace SHA2 {
    template<typename T, typename U>
    T MIN(const T& t1, const U& t2) {
        return (t1 <= t2) ? t1 : t2;
    }
    template<typename T, typename U>
    T MAX(const T& t1, const U& t2) {
        return (t1 >= t2) ? t1 : t2;
    }

    // Bitwise shift right
    template<typename T>
    T SHR(const T& x, const size_t& n) {
        return (x >> n);
    }
    // Bitwise shift left
    template<typename T>
    T SHL(const T& x, const size_t& n) {
        return (x << n);
    }

    // Bitwise rotate right
    template<typename T>
    T ROTR(const T& x, const size_t& n) {
        return ((x) >> (n) | (x) << ((sizeof(x) << 3) - (n)));
    }
    // Bitwise rotate left
    template<typename T>
    T ROTL(const T& x, const size_t& n) {
        return ((x) << (n) | (x) >> ((sizeof(x) << 3) - (n)));
    }

    std::string BinaryToHexString(const uint8_t* inBinaryData, size_t inBinaryDataLength);
    void u32_to_u8(const uint32_t& u32, uint8_t* u8);
    void u8_to_u32(const uint8_t* u8, uint32_t* u32);
}