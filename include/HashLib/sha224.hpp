#pragma once

#include <HashLib/sha2.hpp>

namespace SHA2::SHA224 {
    using HashType  = std::array<uint8_t,32>;  // 32 * 8bits  = 256bits  => 64bytes  | Digest
    using StateType = std::array<uint32_t,8>;  // 8  * 32bits = 256bits  => 64bytes  | Working variables
    using BlockType = std::array<uint32_t,16>; // 16 * 32bits = 512bits  => 128bytes | Big endian block
    using DataType  = std::array<uint8_t,64>;  // 32 * 8bits  = 512bits  => 128bytes | Small endian block
    using MSType    = std::array<uint32_t,64>; // 64 * 32bits = 2048bits => 512bytes | Message schedule

    // BIG sigma functions of SHA224
    uint32_t BSIG_0(const uint32_t& x);
    uint32_t BSIG_1(const uint32_t& x);

    // SMALL sigma functions of SHA224
    uint32_t SSIG_0(const uint32_t& x);
    uint32_t SSIG_1(const uint32_t& x);

    uint32_t CH(const uint32_t& x, const uint32_t& y, const uint32_t& z);
    uint32_t MAJ(const uint32_t& x, const uint32_t& y, const uint32_t& z);

    // SHA224 constants
    static constexpr MSType K = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    void setMsg(const uint8_t* ItMsg, const size_t& msgSize, StateType& H, DataType& data, size_t& data_cursor);
    void padding(const size_t& msgSize, DataType& data, size_t& data_cursor, MSType& W, StateType& WV, StateType& H);

    void compute(DataType& data, MSType& W, StateType& WV, StateType& H);
    [[nodiscard]] std::string hash(const std::string& msg);
}