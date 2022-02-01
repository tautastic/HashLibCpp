#include <HashLib/sha512.hpp>

namespace SHA2::SHA512 {
    // BIG sigma functions of SHA512
    uint64_t BSIG_0(const uint64_t& x) {
        return ((ROTR(x, 28) ^ ROTR(x, 34)) ^ ROTR(x, 39));
    }
    uint64_t BSIG_1(const uint64_t& x) {
        return ((ROTR(x, 14) ^ ROTR(x, 18)) ^ ROTR(x, 41));
    }
    // SMALL sigma functions of SHA512
    uint64_t SSIG_0(const uint64_t& x) {
        return ((ROTR(x, 1) ^ ROTR(x, 8)) ^ SHR(x, 7));
    }
    uint64_t SSIG_1(const uint64_t& x) {
        return ((ROTR(x, 19) ^ ROTR(x, 61)) ^ SHR(x, 6));
    }
    uint64_t CH(const uint64_t& x, const uint64_t& y, const uint64_t& z) {
        return (((x) & (y)) ^ (~(x) & (z)));
    }
    uint64_t MAJ(const uint64_t& x, const uint64_t& y, const uint64_t& z) {
        return (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)));
    }

    void setMsg(const uint8_t* ItMsg, const size_t& msgSize, StateType& H, DataType& data, size_t& data_cursor) {
        size_t msg_cursor = 0;
        MSType W = {};
        StateType WV = {};
        while(msg_cursor < msgSize) {
            size_t numBytesLeft = MIN(sizeof(BlockType) - data_cursor, msgSize - msg_cursor);
            for(size_t j = 0; j < msgSize - msg_cursor && j < sizeof(BlockType); j++) {
                data[j] = ItMsg[j + msg_cursor];
            }
            msg_cursor += numBytesLeft;
            data_cursor += numBytesLeft;
            if(data_cursor == sizeof(BlockType)) {
                // Reached end of block
                // call hash func
                compute(data,W,WV,H);
                // reset data cursor
                data_cursor = 0;
            }
        }
        // Pad final block
        padding(msgSize, data, data_cursor, W, WV, H);
    }

    void padding(const size_t& msgSize, DataType& data, size_t& data_cursor, MSType& W, StateType& WV, StateType& H) {
        // Place 1bit at end
        data[data_cursor++] = 0x80;
        // Clear block after 1bit
        memset(&data[data_cursor], 0, MAX(sizeof(BlockType) - data_cursor, 0));

        if(data_cursor >= sizeof(DataType) - 16) {
            // Need new block for message length
            // Hash old block
            compute(data,W,WV,H);

            // Reset block
            data_cursor = 0;
            memset(&data, 0, sizeof(BlockType));
        }
        // Set last 128bits as message length
        u128_to_u8((msgSize << 3), &data[sizeof(DataType) - 16]);
        compute(data,W,WV,H);
    }

    void compute(DataType& data, MSType& W, StateType& WV, StateType& H) {
        // Prepare the message schedule
        for (size_t j = 0; j < 16; j++) {
            u8_to_u64(&data[j << 3], &W[j]);
        }
        for (size_t j = 16; j < 80; j++) {
            W[j] = SSIG_0(W[j - 15]) + W[j - 16] + SSIG_1(W[j - 2]) + W[j - 7];
        }
        // Initialize the eight working variables, a, b, c, d, e, f, g, and h
        for (size_t j = 0; j < 8; j++) {
            WV[j] = H[j];
        }
        // Run through rounds
        for (size_t j = 0; j < 80; j++) {
            uint64_t t1 = WV[7] + BSIG_1(WV[4]) + CH(WV[4], WV[5], WV[6]) + K[j] + W[j];
            uint64_t t2 = BSIG_0(WV[0]) + MAJ(WV[0], WV[1], WV[2]);
            WV[7] = WV[6];
            WV[6] = WV[5];
            WV[5] = WV[4];
            WV[4] = WV[3] + t1;
            WV[3] = WV[2];
            WV[2] = WV[1];
            WV[1] = WV[0];
            WV[0] = t1 + t2;
        }
        // Update state
        for (size_t j = 0; j < 8; j++) {
            H[j] += WV[j];
        }
    }

    std::string hash(const std::string& msg) {
        DataType data = {};
        HashType out = {};
        size_t data_cursor = 0;
        StateType H = {
            0x6a09e667f3bcc908ULL,
            0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL,
            0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL,
            0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL,
            0x5be0cd19137e2179ULL
        };

        // Start hashing process
        setMsg(reinterpret_cast<const uint8_t*>(msg.data()),msg.size(),H,data,data_cursor);

        // Copy final state to output
        for (size_t i = 0; i < 8; i++) {
            u64_to_u8(H[i], &out[i << 3]);
        }

        // Copy output hash to output string
        std::string hashStr;
        for(int i = 0; i < 64; i+=4) {
            hashStr += BinaryToHexString(&out[i],4);
        }
        return hashStr;
    }
}