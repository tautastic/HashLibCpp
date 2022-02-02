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
    template<typename T>
    T SHR(const T& x, const size_t& n) {
        return (x >> n);
    }
    template<typename T>
    T SHL(const T& x, const size_t& n) {
        return (x << n);
    }
    template<typename T>
    T ROTR(const T& x, const size_t& n) {
        return ((x) >> (n) | (x) << ((sizeof(x) << 3) - (n)));
    }
    template<typename T>
    T ROTL(const T& x, const size_t& n) {
        return ((x) << (n) | (x) >> ((sizeof(x) << 3) - (n)));
    }

    std::string BinaryToHexString(const uint8_t* inBinaryData, size_t inBinaryDataLength);
    void u32_to_u8(const uint32_t& u32, uint8_t* u8);
    void u8_to_u32(const uint8_t* u8, uint32_t* u32);

    void u64_to_u8(const uint64_t& u64, uint8_t* u8);
    void u8_to_u64(const uint8_t* u8, uint64_t* u64);
}

namespace SHA2::SHA224_256 {
    using HashType  = std::array<uint8_t,32>;  // 32 * 8bits  = 256bits  => 32bytes  | Digest
    using StateType = std::array<uint32_t,8>;  // 8  * 32bits = 256bits  => 32bytes  | Working variables
    using BlockType = std::array<uint32_t,16>; // 16 * 32bits = 512bits  => 64bytes  | Big endian block
    using DataType  = std::array<uint8_t,64>;  // 64 * 8bits  = 512bits  => 64bytes  | Small endian block
    using MSType    = std::array<uint32_t,64>; // 64 * 32bits = 2048bits => 256bytes | Message schedule

    // BIG sigma functions of SHA224/256
    uint32_t BSIG_0(const uint32_t& x);
    uint32_t BSIG_1(const uint32_t& x);

    // SMALL sigma functions of SHA224/256
    uint32_t SSIG_0(const uint32_t& x);
    uint32_t SSIG_1(const uint32_t& x);

    uint32_t CH(const uint32_t& x, const uint32_t& y, const uint32_t& z);
    uint32_t MAJ(const uint32_t& x, const uint32_t& y, const uint32_t& z);

    // SHA224/256 constants
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
}


#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
namespace SHA2::SHA384_512 {
    typedef __uint128_t uint128_t;
    void u128_to_u8(const uint128_t& u128, uint8_t* u8); // Only works with GCC or Clang

    using HashType  = std::array<uint8_t,64>;  // 64  * 8bits  = 512bits  => 64bytes  | Digest
    using StateType = std::array<uint64_t,8>;  // 8   * 64bits = 512bits  => 64bytes  | Working variables
    using BlockType = std::array<uint64_t,16>; // 16  * 64bits = 1024bits => 128bytes | Big endian block
    using DataType  = std::array<uint8_t,128>; // 128 * 8bits  = 1024bits => 128bytes | Small endian block
    using MSType    = std::array<uint64_t,80>; // 80  * 64bits = 5120bits => 640bytes | Message schedule

    // BIG sigma functions of SHA384/SHA512
    uint64_t BSIG_0(const uint64_t& x);
    uint64_t BSIG_1(const uint64_t& x);

    // SMALL sigma functions of SHA384/SHA512
    uint64_t SSIG_0(const uint64_t& x);
    uint64_t SSIG_1(const uint64_t& x);

    uint64_t CH(const uint64_t& x, const uint64_t& y, const uint64_t& z);
    uint64_t MAJ(const uint64_t& x, const uint64_t& y, const uint64_t& z);

    // SHA384/SHA512 constants
    static constexpr MSType K = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
        0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
        0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
        0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
        0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
        0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
        0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
        0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
        0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
        0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
        0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
        0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
        0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
        0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    void setMsg(const uint8_t* ItMsg, const size_t& msgSize, StateType& H, DataType& data, size_t& data_cursor);
    void padding(const size_t& msgSize, DataType& data, size_t& data_cursor, MSType& W, StateType& WV, StateType& H);
    void compute(DataType& data, MSType& W, StateType& WV, StateType& H);
}
#endif