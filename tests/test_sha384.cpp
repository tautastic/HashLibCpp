#include <array>
#include <HashLib/sha384.hpp>

int main() {
    std::array<std::string,5> in = {
        "",
        "abc",
        "Hello World",
        "Helloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855World",
        "7d620e4050b5715dc83e8528cfabcHelloe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855Worldcf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a812c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459baf927da3e"
    };

    std::array<std::string,5> out = {
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f",
        "f4ac86a9cfca1f27de355468239be9654b6e7acdd9571ea429e717302e2d0f9e348dacebb3beb907f5f69896336d93a8",
        "9b8ca125d554d8ecb9c523bc145a6e93d29b62c560fd203e340f50110549261ccad731b3829cc181f508870f49f0e939"
    };

    int i = -1;

    return (std::any_of(in.begin(), in.end(), [&i, &out](std::string msg){
        i++;
        return SHA2::SHA384::hash(msg) != out[i];
    }));
}