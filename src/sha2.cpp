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
        *((u8) + 3) = (uint8_t) ((u32)      );
        *((u8) + 2) = (uint8_t) ((u32) >>  8);
        *((u8) + 1) = (uint8_t) ((u32) >> 16);
        *((u8) + 0) = (uint8_t) ((u32) >> 24);
    }
    void u8_to_u32(const uint8_t* u8, uint32_t* u32) {
        *(u32) = ((uint32_t) *((u8) + 3)      )
               | ((uint32_t) *((u8) + 2) <<  8)
               | ((uint32_t) *((u8) + 1) << 16)
               | ((uint32_t) *((u8) + 0) << 24);
    }
}