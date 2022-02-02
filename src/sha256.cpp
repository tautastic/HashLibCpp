#include <HashLib/sha256.hpp>

namespace SHA2::SHA256 {
    /*
     * 1. Initialize hash values H[0] ... H[7]
     * 2. Start hashing process by calling setMsg(). (See sha2.cpp)
     * 3. Write the final state block to an output block.
     * 4. Return std::string of the output block.
     */
    std::string hash(const std::string& msg) {
        SHA224_256::DataType data = {};
        SHA224_256::HashType out = {};
        size_t data_cursor = 0;
        SHA224_256::StateType H = {
            0x6a09e667UL,
            0xbb67ae85UL,
            0x3c6ef372UL,
            0xa54ff53aUL,
            0x510e527fUL,
            0x9b05688cUL,
            0x1f83d9abUL,
            0x5be0cd19UL
        };
        SHA224_256::setMsg(reinterpret_cast<const uint8_t*>(msg.data()),msg.size(),H,data,data_cursor);
        for (size_t i = 0; i < 8; i++) {
            u32_to_u8(H[i], &out[i << 2]);
        }
        std::string hashStr;
        for(int i = 0; i < 32; i+=4) {
            hashStr += BinaryToHexString(&out[i],4);
        }
        return hashStr;
    }
}