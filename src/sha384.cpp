#include <HashLib/sha384.hpp>

namespace SHA2::SHA384 {
    /*
     * 1. Initialize hash values H[0] ... H[7]
     * 2. Start hashing process by calling setMsg(). (See sha2.cpp)
     * 3. Write leftmost 384bits of the final state block to an output block.
     * 4. Return std::string of the output block.
     */
    std::string hash(const std::string& msg) {
        SHA384_512::DataType data = {};
        SHA384_512::HashType out = {};
        size_t data_cursor = 0;
        SHA384_512::StateType H = {
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4
        };
        SHA384_512::setMsg(reinterpret_cast<const uint8_t*>(msg.data()),msg.size(),H,data,data_cursor);
        for (size_t i = 0; i < 6; i++) {
            u64_to_u8(H[i], &out[i << 3]);
        }
        std::string hashStr;
        for(int i = 0; i < 48; i+=4) {
            hashStr += BinaryToHexString(&out[i],4);
        }
        return hashStr;
    }
}