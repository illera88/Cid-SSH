#pragma once

#include <string>
#include <tuple>

namespace wsinternal {
std::tuple<std::string, std::string, std::string> parse_uri(std::string);
} // namespace wsinternal
