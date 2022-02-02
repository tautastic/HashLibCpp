#if defined(__clang__) || defined(__GNUC__) || defined(__GNUG__)
// Only works with GNU or Clang
#pragma once

#include <HashLib/sha2.hpp>

namespace SHA2::SHA384 {
    [[nodiscard]] std::string hash(const std::string& msg);
}
#endif