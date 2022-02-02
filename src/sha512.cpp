#include <HashLib/sha512.hpp>

namespace SHA2::SHA512 {
    /*
     * 1. Initialize hash values H[0] ... H[7]
     * 2. Start hashing process by calling setMsg(). (See sha2.cpp)
     * 3. Write the final state block to an output block.
     * 4. Return std::string of the output block.
     */
    std::string hash(const std::string& msg) {
        SHA384_512::DataType data = {};
        SHA384_512::HashType out = {};
        size_t data_cursor = 0;
        SHA384_512::StateType H = {
            0x6a09e667f3bcc908ULL,
            0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL,
            0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL,
            0x5be0cd19137e2179ULL
        };
        SHA384_512::setMsg(reinterpret_cast<const uint8_t*>(msg.data()),msg.size(),H,data,data_cursor);
        for (size_t i = 0; i < 8; i++) {
            u64_to_u8(H[i], &out[i << 3]);
        }
        std::string hashStr;
        for(int i = 0; i < 64; i+=4) {
            hashStr += BinaryToHexString(&out[i],4);
        }
        return hashStr;
    }
}