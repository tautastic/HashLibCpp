#pragma once

#include <HashLib/sha2.hpp>

namespace SHA2::SHA256 {
    using HashType  = std::array<uint8_t,32>;  // 32 * 8bits  = 256bits  => 32bytes  | Digest
    using StateType = std::array<uint32_t,8>;  // 8  * 32bits = 256bits  => 32bytes  | Working variables
    using BlockType = std::array<uint32_t,16>; // 16 * 32bits = 512bits  => 64bytes  | Big endian block
    using DataType  = std::array<uint8_t,64>;  // 64 * 8bits  = 512bits  => 64bytes  | Small endian block
    using MSType    = std::array<uint32_t,64>; // 64 * 32bits = 2048bits => 256bytes | Message schedule

    // BIG sigma functions of SHA256
    uint32_t BSIG_0(const uint32_t& x);
    uint32_t BSIG_1(const uint32_t& x);

    // SMALL sigma functions of SHA256
    uint32_t SSIG_0(const uint32_t& x);
    uint32_t SSIG_1(const uint32_t& x);

    uint32_t CH(const uint32_t& x, const uint32_t& y, const uint32_t& z);
    uint32_t MAJ(const uint32_t& x, const uint32_t& y, const uint32_t& z);

    // SHA256 constants
    static constexpr MSType K = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
    };

    void setMsg(const uint8_t* ItMsg, const size_t& msgSize, StateType& H, DataType& data, size_t& data_cursor);
    void padding(const size_t& msgSize, DataType& data, size_t& data_cursor, MSType& W, StateType& WV, StateType& H);

    void compute(DataType& data, MSType& W, StateType& WV, StateType& H);
    [[nodiscard]] std::string hash(const std::string& msg);
}