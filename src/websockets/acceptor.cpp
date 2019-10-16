#include <iostream>
#include <stdexcept>

#include <wsinternal/acceptor.h>

namespace wsinternal {
    acceptor::acceptor(
        net::io_context& io_context,
        const net::ip::address& local_host,
        unsigned short local_port,
        std::function<void(net::ip::tcp::socket)> sockethandler
    ) :
        io_context_(io_context),
        socket_(io_context_),
        localhost_address(local_host),
        acceptor_(
            io_context_,
            net::ip::tcp::endpoint(
                localhost_address,
                local_port
            )
        ),
        sockethandler_(sockethandler)
    {}

    net::ip::tcp::endpoint acceptor::local_endpoint() {
        return acceptor_.local_endpoint();
    }

    void acceptor::accept_connections() {
        try {
            acceptor_.async_accept(socket_,
                std::bind(&acceptor::handle_accept,
                    this,
                    std::placeholders::_1));
        } catch (std::exception& e) {
            std::cerr << "Unable to start accepting connections: " << e.what() << std::endl;
        }
    }

    void acceptor::handle_accept(const std::error_code& error) {
        if (!error) {
            sockethandler_(std::move(socket_));
            
            // Setup the async call to accept again
            accept_connections();
        } else {
            std::cerr << "Error: " << error.message() << std::endl;
        }
    }
}
