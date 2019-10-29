#include <regex>
#include <stdexcept>
#include <string>

#include <wsinternal/uri.h>

namespace wsinternal {
std::tuple<std::string, std::string, std::string> parse_uri(const std::string uri)
{
    const std::regex wss_uri(
        // proto  host          port         path        ignored
        "^wss://(\\w+[^/\?#:]*)(\?::(\\d+))\?(/\?[^\?#]*)\?.*$");

    std::smatch base_match;
    if (!std::regex_match(uri, base_match, wss_uri)) {
        throw std::runtime_error("Invalid URI provided");
    }

    // base_match[0] is the whole string that matched
    std::string host = base_match[1].str();
    std::string port = base_match[2].str();
    std::string path = base_match[3].str();

    if (port == "") {
        port = "443";
    }

    return { host, port, path };
}
} // namespace wsinternal
