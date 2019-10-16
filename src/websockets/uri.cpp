#include <regex>
#include <stdexcept>
#include <string>

#include <wsinternal/uri.h>

namespace wsinternal {
    std::tuple<std::string, unsigned short, std::string> parse_uri(const std::string uri) {
        const std::regex wss_uri(
                // proto  host          port         path        ignored
                "^wss://(\\w+[^/\?#:]*)(\?::(\\d+))\?(/\?[^\?#]*)\?.*$"
        );

        std::smatch base_match;
        if (!std::regex_match(uri, base_match, wss_uri)) {
            throw std::runtime_error("Invalid URI provided");
        }

        // base_match[0] is the whole string that matched
        std::string host = base_match[1].str();
        unsigned short port;
        std::string port_str = base_match[2].str();
        std::string path = base_match[3].str();

        if (port_str == "") {
            port = 443;
        } else {
            port = static_cast<unsigned short>(std::stoul(port_str));
        }

        return {host, port, path};
    }
}
