#include <HashLib/sha224.hpp>

namespace SHA2::SHA224 {
    // BIG sigma functions of SHA256
    uint32_t BSIG_0(const uint32_t& x) {
        return ((ROTR(x, 2) ^ ROTR(x, 13)) ^ ROTR(x, 22));
    }
    uint32_t BSIG_1(const uint32_t& x) {
        return ((ROTR(x, 6) ^ ROTR(x, 11)) ^ ROTR(x, 25));
    }
    // SMALL sigma functions of SHA256
    uint32_t SSIG_0(const uint32_t& x) {
        return ((ROTR(x, 7) ^ ROTR(x, 18)) ^ SHR(x, 3));
    }
    uint32_t SSIG_1(const uint32_t& x) {
        return ((ROTR(x, 17) ^ ROTR(x, 19)) ^ SHR(x, 10));
    }
    uint32_t CH(const uint32_t& x, const uint32_t& y, const uint32_t& z) {
        return (((x) & (y)) ^ (~(x) & (z)));
    }
    uint32_t MAJ(const uint32_t& x, const uint32_t& y, const uint32_t& z) {
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

        if(data_cursor >= 56) {
            // Need new block for message length
            // Hash old block
            compute(data,W,WV,H);

            // Reset block
            data_cursor = 0;
            memset(&data, 0, sizeof(BlockType));
        }
        // Set last 32bits as message length
        u32_to_u8((msgSize << 3), &data[sizeof(BlockType) - 4]);
        compute(data,W,WV,H);
    }

    void compute(DataType& data, MSType& W, StateType& WV, StateType& H) {
        // Prepare the message schedule
        for (size_t j = 0; j < 16; j++) {
            u8_to_u32(&data[j << 2], &W[j]);
        }
        for (size_t j = 16; j < 64; j++) {
            W[j] = SSIG_0(W[j - 15]) + W[j - 16] + SSIG_1(W[j - 2]) + W[j - 7];
        }
        // Initialize the eight working variables, a, b, c, d, e, f, g, and h
        for (size_t j = 0; j < 8; j++) {
            WV[j] = H[j];
        }
        // Run through rounds
        for (size_t j = 0; j < 64; j++) {
            uint32_t t1 = WV[7] + BSIG_1(WV[4]) + CH(WV[4], WV[5], WV[6]) + K[j] + W[j];
            uint32_t t2 = BSIG_0(WV[0]) + MAJ(WV[0], WV[1], WV[2]);
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
            0xc1059ed8U,0x367cd507U,
            0x3070dd17U,0xf70e5939U,
            0xffc00b31U,0x68581511U,
            0x64f98fa7U,0xbefa4fa4U
        };

        // Start hashing process
        setMsg(reinterpret_cast<const uint8_t*>(msg.data()),msg.size(),H,data,data_cursor);

        // Copy leftmost 224bits of the final state to output
        for (size_t i = 0; i < 7; i++) {
            u32_to_u8(H[i], &out[i << 2]);
        }

        // Copy leftmost 224bits of the output hash to output string
        std::string hashStr;
        for(int i = 0; i < 28; i+=4) {
            hashStr += BinaryToHexString(&out[i],4);
        }
        return hashStr;
    }
}