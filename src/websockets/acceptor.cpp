#include <iostream>
#include <stdexcept>

#include <boost/asio/strand.hpp>

#include <wsinternal/acceptor.h>

namespace wsinternal {
acceptor::acceptor(
    net::any_io_executor executor,
    const net::ip::address& local_host,
    unsigned short local_port,
    std::function<void(net::ip::tcp::socket&&)> sockethandler)
    : executor_(executor)
    , acceptor_(
          net::make_strand(executor_),
          net::ip::tcp::endpoint { local_host, local_port },
          true // reuse address
          )
    , sockethandler_(sockethandler)
{
}

acceptor::acceptor(
    net::any_io_executor executor,
    net::ip::tcp::endpoint endpoint,
    std::function<void(net::ip::tcp::socket&&)> sockethandler)
    : executor_(executor)
    , acceptor_(
          net::make_strand(executor_),
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
            net::make_strand(executor_),
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
