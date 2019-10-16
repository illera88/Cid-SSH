#ifndef WSCONN_H_9EDF7CB75D0C61
#define WSCONN_H_9EDF7CB75D0C61

#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>

namespace wsinternal {
    namespace beast = boost::beast;
    namespace net = boost::asio;

    typedef beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>> wsstream;

    class wsconn : public std::enable_shared_from_this<wsconn> {
            wsconn(
                net::io_context& io_context,
                net::ssl::context& ssl_context,
                std::string& uri,
                std::function<void(wsstream)> sockethandler
            );

        public:
            // Ah, C++ templating can be such a joy
            template<typename ... T>
            static auto create(T&& ... all) {
                // Can't use make_shared here because of visibility rules and
                // all that fun jazz...
                auto ptr = std::shared_ptr<wsconn>(new wsconn(std::forward<T>(all)...));
                ptr->start();
                return ptr;
            }

        private:
            void start();
            void on_connect(const std::error_code& error, net::ip::tcp::resolver::results_type::endpoint_type);
            void on_ssl_handshake(const std::error_code& error);
            void on_handshake(const std::error_code& error);

            net::io_context& io_context_;
            net::ssl::context& ssl_context_;
            net::ip::tcp::resolver resolver_;
            wsstream ws_;
            std::string& uri_;
            std::function<void(wsstream)> sockethandler_;

            std::string host_;
            std::string port_;
            std::string path_;
    };
}

#endif /* WSCONN_H_9EDF7CB75D0C61 */
