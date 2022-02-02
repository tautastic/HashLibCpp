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

    /*
     * Write the data of one 32bit unsigned long to
     * four 8bit unsigned ints.
     */
    void u32_to_u8(const uint32_t& u32, uint8_t* u8) {
        *(u8 + 3) = static_cast<uint8_t>(u32      );
        *(u8 + 2) = static_cast<uint8_t>(u32 >>  8);
        *(u8 + 1) = static_cast<uint8_t>(u32 >> 16);
        *(u8 + 0) = static_cast<uint8_t>(u32 >> 24);
    }

    /*
     * Write the data of four 8bit unsigned ints to
     * one 32bit unsigned long.
     */
    void u8_to_u32(const uint8_t* u8, uint32_t* u32) {
        *(u32) = (static_cast<uint32_t>(*(u8 + 3))   )
            | (static_cast<uint32_t>(*(u8 + 2)) <<  8)
            | (static_cast<uint32_t>(*(u8 + 1)) << 16)
            | (static_cast<uint32_t>(*(u8 + 0)) << 24);
    }

    /*
     * Write the data of one 64bit unsigned long long to
     * eight 8bit unsigned ints.
     */
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

    /*
     * Write the data of eight 8bit unsigned ints to
     * one 64bit unsigned long long.
     */
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
}

namespace SHA2::SHA224_256 {
    // BIG sigma SHA224/256
    uint32_t BSIG_0(const uint32_t& x) {
        return ((ROTR(x, 2) ^ ROTR(x, 13)) ^ ROTR(x, 22));
    }
    uint32_t BSIG_1(const uint32_t& x) {
        return ((ROTR(x, 6) ^ ROTR(x, 11)) ^ ROTR(x, 25));
    }
    // SMALL sigma SHA224/256
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

    /*
     * Write message to 512bit blocks:
     *      When a block is filled before the whole message is processed:
     *          Compute intermediate hash without padding the current block
     *
     *      When the whole message is processed:
     *          Pad the current block
     */
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
                compute(data,W,WV,H);
                data_cursor = 0;
            }
        }
        padding(msgSize, data, data_cursor, W, WV, H);
    }

    /*
     * 1. Append a 1 bit to the end of the message, and set the rest of the block to 0 bits.
     *
     * 2. If the last 64 bits (8 bytes) of the block are not 0 bits:
     *      1. Compute intermediate hash of the current block.
     *      2. Clear the block by setting every bit to a 0 bit.
     *
     * 3. Set the last 64 bits of the block to the message length.
     */
    void padding(const size_t& msgSize, DataType& data, size_t& data_cursor, MSType& W, StateType& WV, StateType& H) {
        data[data_cursor++] = 0x80;
        memset(&data[data_cursor], 0, MAX(sizeof(BlockType) - data_cursor, 0));
        if(data_cursor >= sizeof(DataType) - 8) {
            compute(data,W,WV,H);
            data_cursor = 0;
            memset(&data, 0, sizeof(BlockType));
        }
        u64_to_u8((msgSize << 3), &data[sizeof(DataType) - 8]);
        compute(data,W,WV,H);
    }

    /*
     * 1. Prepare message schedule W[]:
     *      Copy the 512bit msg block to W[0] ... W[15].
     *      In this step 64 8bit unsigned ints are copied to 16 32bit unsigned longs.
     *
     * 2. Initialize the eight working variables WV[0] ... WV[7].
     * 3. Go through the compression function for 64 rounds.
     * 4. Update H[0] ... H[7] by adding the final value of the working variables WV[0] ... WV[7]
     */
    void compute(DataType& data, MSType& W, StateType& WV, StateType& H) {
        for (size_t j = 0; j < 16; j++) {
            u8_to_u32(&data[j << 2], &W[j]);
        }
        for (size_t j = 16; j < 64; j++) {
            W[j] = SSIG_0(W[j - 15]) + W[j - 16] + SSIG_1(W[j - 2]) + W[j - 7];
        }
        for (size_t j = 0; j < 8; j++) {
            WV[j] = H[j];
        }
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
        for (size_t j = 0; j < 8; j++) {
            H[j] += WV[j];
        }
    }
}

namespace SHA2::SHA384_512 {
    /*
     * Write the data of one 128bit unsigned type to
     * sixteen 8bit unsigned ints.
     */
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

    // BIG sigma functions of SHA384/SHA512
    uint64_t BSIG_0(const uint64_t& x) {
        return ((ROTR(x, 28) ^ ROTR(x, 34)) ^ ROTR(x, 39));
    }
    uint64_t BSIG_1(const uint64_t& x) {
        return ((ROTR(x, 14) ^ ROTR(x, 18)) ^ ROTR(x, 41));
    }
    // SMALL sigma functions of SHA384/SHA512
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

    /*
     * Write message to 1024bit blocks:
     *      When a block is filled before the whole message is processed:
     *          Compute intermediate hash without padding the current block
     *
     *      When the whole message is processed:
     *          Pad the current block
     */
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
                compute(data,W,WV,H);
                data_cursor = 0;
            }
        }
        padding(msgSize, data, data_cursor, W, WV, H);
    }

    /*
     * 1. Append a 1 bit to the end of the message, and set the rest of the block to 0 bits.
     *
     * 2. If the last 128 bits (16 bytes) of the block are not 0 bits:
     *      1. Compute intermediate hash of the current block.
     *      2. Clear the block by setting every bit to a 0 bit.
     *
     * 3. Set the last 128 bits of the block to the message length.
     */
    void padding(const size_t& msgSize, DataType& data, size_t& data_cursor, MSType& W, StateType& WV, StateType& H) {
        data[data_cursor++] = 0x80;
        memset(&data[data_cursor], 0, MAX(sizeof(BlockType) - data_cursor, 0));

        if(data_cursor >= sizeof(DataType) - 16) {
            compute(data,W,WV,H);
            data_cursor = 0;
            memset(&data, 0, sizeof(BlockType));
        }
        u128_to_u8((msgSize << 3), &data[sizeof(DataType) - 16]);
        compute(data,W,WV,H);
    }

    /*
     * 1. Prepare message schedule W[]:
     *      Copy the 1024bit msg block to W[0] ... W[15].
     *      In this step 128 8bit unsigned ints are copied to 16 64bit unsigned long longs.
     *
     * 2. Initialize the eight working variables WV[0] ... WV[7].
     * 3. Go through the compression function for 80 rounds.
     * 4. Update H[0] ... H[7] by adding the final value of the working variables WV[0] ... WV[7]
     */
    void compute(DataType& data, MSType& W, StateType& WV, StateType& H) {
        // Prepare the message schedule
        for (size_t j = 0; j < 16; j++) {
            u8_to_u64(&data[j << 3], &W[j]);
        }
        for (size_t j = 16; j < 80; j++) {
            W[j] = SSIG_0(W[j - 15]) + W[j - 16] + SSIG_1(W[j - 2]) + W[j - 7];
        }
        for (size_t j = 0; j < 8; j++) {
            WV[j] = H[j];
        }
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
        for (size_t j = 0; j < 8; j++) {
            H[j] += WV[j];
        }
    }
}