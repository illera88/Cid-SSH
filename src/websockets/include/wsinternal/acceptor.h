#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace wsinternal {
    namespace net = boost::asio;

    class acceptor {
        public:
            acceptor(
                net::io_context& io_context,
                const net::ip::address_v4& local_host,
                unsigned short local_port,
                std::function<void(net::ip::tcp::socket)> sockethandler
            );
            net::ip::tcp::endpoint local_endpoint();
            void accept_connections();
        private:
            void handle_accept(const std::error_code& error);

            net::io_context& io_context_;
            net::ip::tcp::socket socket_;
            net::ip::address localhost_address;
            net::ip::tcp::acceptor acceptor_;
            std::function<void(net::ip::tcp::socket)> sockethandler_;
    };
}
