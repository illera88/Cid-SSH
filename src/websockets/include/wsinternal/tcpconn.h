#ifndef TCPCONN_H_D6AD02BDB9EF17
#define TCPCONN_H_D6AD02BDB9EF17

#include <memory>

#include <boost/asio/executor.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <socks/uri.hpp>

namespace wsinternal {
namespace net = boost::asio;

class tcpconn : public std::enable_shared_from_this<tcpconn> {
    tcpconn(
        net::executor,
        std::string&,
        const std::string&,
        std::function<void(net::ip::tcp::socket&&)>,
        std::function<void(const std::error_code&)>);

public:
    // Ah, C++ templating can be such a joy
    template <typename... T>
    static auto create(T&&... all)
    {
        // Can't use make_shared here because of visibility rules and
        // all that fun jazz...
        auto ptr = std::shared_ptr<tcpconn>(new tcpconn(std::forward<T>(all)...));
        ptr->start();
        return ptr;
    }

private:
    void start();
    void on_resolve(
        const std::error_code&,
        net::ip::tcp::resolver::results_type);
    void on_connect(
        const std::error_code&,
        net::ip::tcp::resolver::results_type::endpoint_type);
    void handshake(const std::error_code&);

    net::executor executor_;
    net::ip::tcp::resolver resolver_;
    std::function<void(net::ip::tcp::socket&&)> sockethandler_;
    std::function<void(const std::error_code&)> errorhandler_;
    net::ip::tcp::socket socket_;

    std::string& remote_uri_;
    std::string host_;
    std::string port_;
    std::string path_;
    const std::string& proxy_uri_;
    socks::uri socks_uri_;
};
} // namespace wsinternal


#endif /* TCPCONN_H_D6AD02BDB9EF17 */
