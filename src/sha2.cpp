#include <HashLib/sha2.hpp>

namespace SHA2 {
    std::string BinaryToHexString(const uint8_t* inBinaryData, size_t inBinaryDataLength){
        static const char *hexDigits = "0123456789ABCDEF";
        std::string hexString;
        hexString.reserve(inBinaryDataLength * 2);
        // Run through the binary data and convert to a hex string
        std::for_each(
            inBinaryData,
            inBinaryData + inBinaryDataLength,
            [&hexString](uint8_t inputByte) {
                hexString.push_back(tolower(hexDigits[inputByte >> 4]));
                hexString.push_back(tolower(hexDigits[inputByte & 0x0F]));
            });
        return hexString;
    }

    void u32_to_u8(const uint32_t& u32, uint8_t* u8) {
        *(u8 + 3) = static_cast<uint8_t>(u32      );
        *(u8 + 2) = static_cast<uint8_t>(u32 >>  8);
        *(u8 + 1) = static_cast<uint8_t>(u32 >> 16);
        *(u8 + 0) = static_cast<uint8_t>(u32 >> 24);
    }
    void u8_to_u32(const uint8_t* u8, uint32_t* u32) {
        *(u32) = (static_cast<uint32_t>(*(u8 + 3))   )
            | (static_cast<uint32_t>(*(u8 + 2)) <<  8)
            | (static_cast<uint32_t>(*(u8 + 1)) << 16)
            | (static_cast<uint32_t>(*(u8 + 0)) << 24);
    }


    void u64_to_u8(const uint64_t& u64, uint8_t* u8) {
        *(u8 + 7) = static_cast<uint8_t>(u64      );
        *(u8 + 6) = static_cast<uint8_t>(u64 >>  8);
        *(u8 + 5) = static_cast<uint8_t>(u64 >> 16);
        *(u8 + 4) = static_cast<uint8_t>(u64 >> 24);
        *(u8 + 3) = static_cast<uint8_t>(u64 >> 32);
        *(u8 + 2) = static_cast<uint8_t>(u64 >> 40);
        *(u8 + 1) = static_cast<uint8_t>(u64 >> 48);
        *(u8 + 0) = static_cast<uint8_t>(u64 >> 56);
    }
    void u8_to_u64(const uint8_t* u8, uint64_t* u64) {
        *(u64) = (static_cast<uint64_t>(*(u8 + 7))   )
            | (static_cast<uint64_t>(*(u8 + 6)) <<  8)
            | (static_cast<uint64_t>(*(u8 + 5)) << 16)
            | (static_cast<uint64_t>(*(u8 + 4)) << 24)
            | (static_cast<uint64_t>(*(u8 + 3)) << 32)
            | (static_cast<uint64_t>(*(u8 + 2)) << 40)
            | (static_cast<uint64_t>(*(u8 + 1)) << 48)
            | (static_cast<uint64_t>(*(u8 + 0)) << 56);
    }
    #if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
    void u128_to_u8(const uint128_t& u128, uint8_t* u8) {
        *(u8 + 15) = static_cast<uint8_t>(u128      );
        *(u8 + 14) = static_cast<uint8_t>(u128 >>  8);
        *(u8 + 13) = static_cast<uint8_t>(u128 >> 16);
        *(u8 + 12) = static_cast<uint8_t>(u128 >> 24);
        *(u8 + 11) = static_cast<uint8_t>(u128 >> 32);
        *(u8 + 10) = static_cast<uint8_t>(u128 >> 40);
        *(u8 + 9)  = static_cast<uint8_t>(u128 >> 48);
        *(u8 + 8)  = static_cast<uint8_t>(u128 >> 56);
        *(u8 + 7)  = static_cast<uint8_t>(u128 >> 64);
        *(u8 + 6)  = static_cast<uint8_t>(u128 >> 72);
        *(u8 + 5)  = static_cast<uint8_t>(u128 >> 80);
        *(u8 + 4)  = static_cast<uint8_t>(u128 >> 88);
        *(u8 + 3)  = static_cast<uint8_t>(u128 >> 96);
        *(u8 + 2)  = static_cast<uint8_t>(u128 >> 104);
        *(u8 + 1)  = static_cast<uint8_t>(u128 >> 112);
        *(u8 + 0)  = static_cast<uint8_t>(u128 >> 120);
    }
    #endif
}