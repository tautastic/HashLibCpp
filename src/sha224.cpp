#include <HashLib/sha224.hpp>

namespace SHA2::SHA224 {
    /*
     * 1. Initialize hash values H[0] ... H[7]
     * 2. Start hashing process by calling setMsg(). (See sha2.cpp)
     * 3. Write leftmost 224bits of the final state block to an output block.
     * 4. Return std::string of the output block.
     */
    std::string hash(const std::string& msg) {
        SHA224_256::DataType data = {};
        SHA224_256::HashType out = {};
        size_t data_cursor = 0;
        SHA224_256::StateType H = {
            0xc1059ed8UL,
            0x367cd507UL,
            0x3070dd17UL,
            0xf70e5939UL,
            0xffc00b31UL,
            0x68581511UL,
            0x64f98fa7UL,
            0xbefa4fa4UL
        };
        SHA224_256::setMsg(reinterpret_cast<const uint8_t*>(msg.data()),msg.size(),H,data,data_cursor);
        for (size_t i = 0; i < 7; i++) {
            u32_to_u8(H[i], &out[i << 2]);
        }
        std::string hashStr;
        for(int i = 0; i < 28; i+=4) {
            hashStr += BinaryToHexString(&out[i],4);
        }
        return hashStr;
    }
}