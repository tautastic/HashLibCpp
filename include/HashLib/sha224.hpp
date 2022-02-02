#pragma once

#include <HashLib/sha2.hpp>

namespace SHA2::SHA224 {
    [[nodiscard]] std::string hash(const std::string& msg);
}