#ifndef ACCEPTOR_H_4ADCB5B556AEB7
#define ACCEPTOR_H_4ADCB5B556AEB7

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace wsinternal {
    namespace net = boost::asio;

    class acceptor {
        public:
            acceptor(
                net::io_context& io_context,
                const net::ip::address& local_host,
                unsigned short local_port,
                std::function<void(net::ip::tcp::socket&&)> sockethandler
            );

            acceptor(
                net::io_context& io_context,
                net::ip::tcp::endpoint endpoint,
                std::function<void(net::ip::tcp::socket&&)> sockethandler
            );

            net::ip::tcp::endpoint local_endpoint();
            void accept_connections();
        private:
            void handle_accept(const std::error_code& error, net::ip::tcp::socket);

            net::io_context& io_context_;
            net::ip::address localhost_address;
            net::ip::tcp::acceptor acceptor_;
            std::function<void(net::ip::tcp::socket&&)> sockethandler_;
    };
}

#endif /* ACCEPTOR_H_4ADCB5B556AEB7 */
