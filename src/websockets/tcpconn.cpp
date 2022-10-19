#include <iostream>
#include <memory>
#include <string_view>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <socks/handshake.hpp>
#include <socks/uri.hpp>

#include <httpconnect.hpp>
#include <wsinternal/tcpconn.h>
#include <wsinternal/uri.h>

namespace wsinternal {
namespace net = boost::asio;

tcpconn::tcpconn(
    net::any_io_executor executor,
    std::string& remote_uri,
    const std::string& proxy_uri,
    std::function<void(net::ip::tcp::socket&&)> sockethandler,
    std::function<void(const std::error_code&)> errorhandler)
    : executor_(executor)
    , resolver_(net::make_strand(executor_))
    , remote_uri_(remote_uri)
    , proxy_uri_(proxy_uri)
    , sockethandler_(sockethandler)
    , errorhandler_(errorhandler)
    , socket_(net::make_strand(executor_))
{
    std::tie(host_, port_, path_) = parse_uri(remote_uri_);

    if (!socks_uri_.parse(proxy_uri_)) {
        std::cerr << "Unable to parse the proxy uri" << std::endl;
        socks_uri_.parse("direct://");
    }
}

void tcpconn::start()
{
    std::string host;
    std::string port;

    if (socks_uri_.scheme() != "direct") {
        host = std::string(socks_uri_.host());
        port = std::string(socks_uri_.port());
    } else {
        host = host_;
        port = port_;
    }

    resolver_.async_resolve(
        host,
        port,
        std::bind(
            &tcpconn::on_resolve,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
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
        errorhandler_(error);
    }
}

void tcpconn::on_connect(const std::error_code& error, net::ip::tcp::resolver::results_type::endpoint_type)
{
    if (!error) {
        auto socks_version_ = 0;
        auto use_socks = false;

        if (socks_uri_.scheme() == "socks5") {
            socks_version_ = 5;
            use_socks = true;
        } else if (socks_uri_.scheme() == "socks4") {
            socks_version_ = 4;
            use_socks = true;
        }

        if (use_socks) {
            switch (socks_version_) {
            case 5:
                socks::async_handshake_v5(
                    socket_,
                    host_,
                    static_cast<unsigned short>(std::atoi(port_.c_str())),
                    std::string(socks_uri_.username()),
                    std::string(socks_uri_.password()),
                    true,
                    std::bind(&tcpconn::handshake,
                        shared_from_this(),
                        std::placeholders::_1));
                break;
            case 4:
                socks::async_handshake_v4(
                    socket_,
                    host_,
                    static_cast<unsigned short>(std::atoi(port_.c_str())),
                    std::string(socks_uri_.username()),
                    std::bind(&tcpconn::handshake,
                        shared_from_this(),
                        std::placeholders::_1));
                break;
            default:
                sockethandler_(std::move(socket_));
                break;
            }
        } else if (socks_uri_.scheme() == "http" || socks_uri_.scheme() == "connect") {
            httpconnect::async_handshake_httpconnect(
                socket_,
                host_,
                port_,
                std::string(socks_uri_.username()),
                std::string(socks_uri_.password()),
                std::bind(&tcpconn::handshake,
                    shared_from_this(),
                    std::placeholders::_1));
        } else {
            sockethandler_(std::move(socket_));
        }
    } else {
        std::cerr << "Failed to connect: " << error.message() << std::endl;
        errorhandler_(error);
    }
}

void tcpconn::handshake(const std::error_code& error)
{
    if (!error) {
        sockethandler_(std::move(socket_));
    } else {
        std::cerr << "Failed to handshake the proxy: " << error.message() << std::endl;
        errorhandler_(error);
    }
}

} // namespace wsinternal
