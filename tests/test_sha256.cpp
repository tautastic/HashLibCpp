#include <array>
#include <HashLib/sha256.hpp>

int main() {
    std::array<std::string,5> in = {
        "",
        "abc",
        "Hello World",
        "Helloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855World",
        "7d620e4050b5715dc83e8528cfabcHelloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855Worldcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a812c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459baf927da3e"
    };

    std::array<std::string,5> out = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
        "8e93cb594f28880bcaaf9f14c4461cb6fa1f8fe1ae5693f20f31172af520bc6b",
        "7525c67fce05e54a89ad04dfcbc93a022989be4c3107b4059b0d82ff82f73ea7"
    };

    int i = -1;

    return (std::any_of(in.begin(), in.end(), [&i, &out](std::string msg){
        i++;
        return SHA2::SHA256::hash(msg) != out[i];
    }));
}