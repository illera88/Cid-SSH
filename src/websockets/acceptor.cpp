#include <iostream>
#include <stdexcept>

#include <boost/asio/strand.hpp>

#include <wsinternal/acceptor.h>

namespace wsinternal {
acceptor::acceptor(
    net::io_context& io_context,
    const net::ip::address& local_host,
    unsigned short local_port,
    std::function<void(net::ip::tcp::socket&&)> sockethandler)
    : io_context_(io_context)
    , acceptor_(
          net::make_strand(io_context_),
          net::ip::tcp::endpoint { local_host, local_port },
          true // reuse address
          )
    , sockethandler_(sockethandler)
{
}

acceptor::acceptor(
    net::io_context& io_context,
    net::ip::tcp::endpoint endpoint,
    std::function<void(net::ip::tcp::socket&&)> sockethandler)
    : io_context_(io_context)
    , acceptor_(
          net::make_strand(io_context_),
          endpoint,
          true // reuse address
          )
    , sockethandler_(sockethandler)
{
}

net::ip::tcp::endpoint acceptor::local_endpoint()
{
    return acceptor_.local_endpoint();
}

void acceptor::accept_connections()
{
    try {
        acceptor_.async_accept(
            net::make_strand(io_context_),
            std::bind(&acceptor::handle_accept,
                this,
                std::placeholders::_1,
                std::placeholders::_2));
    } catch (std::exception& e) {
        std::cerr << "Unable to start accepting connections: " << e.what() << std::endl;
    }
}

void acceptor::handle_accept(const std::error_code& error, net::ip::tcp::socket socket)
{
    if (!error) {
        sockethandler_(std::move(socket));

        // Setup the async call to accept again
        accept_connections();
    } else {
        std::cerr << "Error: " << error.message() << std::endl;
    }
}
} // namespace wsinternal
