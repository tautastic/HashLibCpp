#include <array>
#include <HashLib/sha224.hpp>


using namespace SHA2::SHA224;

int main() {
    std::array<std::string,5> in = {
        "",
        "abc",
        "Hello World",
        "Helloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855World",
        "7d620e4050b5715dc83e8528cfabcHelloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855Worldcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a812c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459baf927da3e"
    };

    std::array<std::string,5> out = {
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
        "c4890faffdb0105d991a461e668e276685401b02eab1ef4372795047",
        "e1cac01d0e55dda09e67b152160ddf3e315c19c233ab6aca57d78cf4",
        "bf49dc84e82beb3dae9164b833d3c5876ff2fe69613809c33d5ecb65"
    };

    int i = -1;

    return (std::any_of(in.begin(), in.end(), [&i, &out](std::string msg){
        i++;
        return hash(msg) != out[i];
    }));
}