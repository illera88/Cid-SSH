#pragma once

#include <memory>

#include <boost/asio/executor.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>

namespace wsinternal {
namespace beast = boost::beast;
namespace net = boost::asio;

typedef beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>> wsstream;

class wsconn : public std::enable_shared_from_this<wsconn> {
    wsconn(
        net::any_io_executor,
        net::ip::tcp::socket&& socket,
        net::ssl::context&,
        std::function<void(wsstream&&)>);

public:
    // Ah, C++ templating can be such a joy
    template <typename... T>
    static auto create(T&&... all)
    {
        // Can't use make_shared here because of visibility rules and
        // all that fun jazz...
        auto ptr = std::shared_ptr<wsconn>(new wsconn(std::forward<T>(all)...));
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
    void on_ssl_handshake(const std::error_code&);
    void on_handshake(const std::error_code&);

    net::any_io_executor executor_;
    net::ssl::context& ssl_context_;
    net::ip::tcp::resolver resolver_;
    wsstream ws_;
    std::function<void(wsstream&&)> sockethandler_;
};
} // namespace wsinternal
