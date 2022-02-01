#include <array>
#include <HashLib/sha512.hpp>


using namespace SHA2::SHA512;

int main() {
    std::array<std::string,5> in = {
        "",
        "ab",
        "Hello World",
        "Helloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855World",
        "7d620e4050b5715dc83e8528cfabcHelloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855Worldcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a812c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459baf927da3e"
    };

    std::array<std::string,5> out = {
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b",
        "498af304cc5446e8528cf927393e4495dc95ce4cb217debf1032f7131fa46496d8873c3175263d255b5531212fe5a097496f205c67a3a4814e516ada8aa150fc",
        "5e89f6ba849ce85a26124d9ae7e72232a6c34d0a7c19ae11fbc817a2c7d8df22e6a57d5ebc286e898f46a7ed4c19c7f2a0079bfc650f18e98217e020ffd04b3e"
    };

    int i = -1;

    return (std::any_of(in.begin(), in.end(), [&i, &out](std::string msg){
        i++;
        return hash(msg) != out[i];
    }));
}