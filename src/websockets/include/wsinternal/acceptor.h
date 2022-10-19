#pragma once

#include <boost/asio/executor.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace wsinternal {
namespace net = boost::asio;

class acceptor {
public:
    acceptor(
        net::any_io_executor executor,
        const net::ip::address& local_host,
        unsigned short local_port,
        std::function<void(net::ip::tcp::socket&&)> sockethandler);

    acceptor(
        net::any_io_executor executor,
        net::ip::tcp::endpoint endpoint,
        std::function<void(net::ip::tcp::socket&&)> sockethandler);

    net::ip::tcp::endpoint local_endpoint();
    void accept_connections();

private:
    void handle_accept(const std::error_code& error, net::ip::tcp::socket);

    net::any_io_executor executor_;
    net::ip::address localhost_address;
    net::ip::tcp::acceptor acceptor_;
    std::function<void(net::ip::tcp::socket&&)> sockethandler_;
};
} // namespace wsinternal

