#include <iostream>
#include <memory>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <socks/handshake.hpp>
#include <socks/uri.hpp>

#include <wsinternal/tcpconn.h>
#include <wsinternal/uri.h>

namespace wsinternal {
namespace net = boost::asio;

tcpconn::tcpconn(
    net::executor executor,
    std::string& remote_uri,
    std::string& proxy_uri,
    std::function<void(net::ip::tcp::socket&&)> sockethandler)
    : executor_(executor)
    , resolver_(net::make_strand(executor_))
    , remote_uri_(remote_uri)
    , proxy_uri_(proxy_uri)
    , sockethandler_(sockethandler)
    , socket_(net::make_strand(executor_))
{
    std::tie(host_, port_, path_) = parse_uri(remote_uri_);

    if (socks_uri_.parse(proxy_uri_) && socks_uri_.scheme() != "direct") {
        use_proxy_ = true;
    }

    if (socks_uri_.scheme() == "socks5") {
        socks_version_ = 5;
    } else if (socks_uri_.scheme() == "socks4") {
        socks_version_ = 4;
    } else {
        use_proxy_ = false;
    }
}

void tcpconn::start()
{
    if (use_proxy_) {
        resolver_.async_resolve(
            std::string(socks_uri_.host()),
            std::string(socks_uri_.port()),
            std::bind(
                &tcpconn::on_resolve,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2));
    } else {
        resolver_.async_resolve(
            host_,
            port_,
            std::bind(
                &tcpconn::on_resolve,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2));
    }
}

void tcpconn::on_resolve(
    const std::error_code& error,
    net::ip::tcp::resolver::results_type results)
{
    if (!error) {
        // Make the connection on the IP address we get from a lookup
        async_connect(
            socket_,
            results,
            std::bind(
                &tcpconn::on_connect,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2));
    } else {
        std::cerr << "Failed to resolve: " << error.message() << std::endl;
    }
}

void tcpconn::on_connect(const std::error_code& error, net::ip::tcp::resolver::results_type::endpoint_type)
{
    if (!error) {
        if (use_proxy_) {
            switch (socks_version_) {
            case 5:
                socks::async_handshake_v5(
                    socket_,
                    host_,
                    static_cast<unsigned short>(std::atoi(port_.c_str())),
                    std::string(socks_uri_.username()),
                    std::string(socks_uri_.password()),
                    true,
                    std::bind(&tcpconn::socks_handshake,
                        shared_from_this(),
                        std::placeholders::_1));
                break;
            case 4:
                socks::async_handshake_v4(
                    socket_,
                    host_,
                    static_cast<unsigned short>(std::atoi(port_.c_str())),
                    std::string(socks_uri_.username()),
                    std::bind(&tcpconn::socks_handshake,
                        shared_from_this(),
                        std::placeholders::_1));
                break;
            default:
                sockethandler_(std::move(socket_));
                break;
            }
        } else {
            sockethandler_(std::move(socket_));
        }
    } else {
        std::cerr << "Failed to connect: " << error.message() << std::endl;
    }
}

void tcpconn::socks_handshake(const std::error_code& error)
{
    if (!error) {
        sockethandler_(std::move(socket_));
    } else {
        std::cerr << "Failed to handshake socks proxy: " << error.message() << std::endl;
    }
}

} // namespace wsinternal
