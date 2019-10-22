#ifndef BRIDGE_H_000F58BF269299
#define BRIDGE_H_000F58BF269299

#include <iostream>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/beast/websocket/stream.hpp>

namespace wsinternal {
    namespace beast = boost::beast;
    namespace net = boost::asio;

    typedef beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>> wsstream;

    class bridge : public std::enable_shared_from_this<bridge> {
            // Private constructor, use create()
            bridge(net::ip::tcp::socket&& socket, wsstream&& wsocket);

        public:
            // Ah, C++ templating can be such a joy
            template<typename ... T>
            static std::shared_ptr<bridge> create(T&& ... all) {
                // Can't use make_shared here because of visibility rules and
                // all that fun jazz...
                auto ptr = std::shared_ptr<bridge>(new bridge(std::forward<T>(all)...));
                ptr->start();
                return ptr;
            }

        private:
            void start();

            // When we read data from the socket, we write it to the websocket
            void handle_socket_read(
                const std::error_code& error,
                const size_t& bytes_transferred
            );

            // We wrote the data we got from the websocket to the socket, so
            // now we can read more data from the websocket
            void handle_socket_write(const std::error_code& error);

            // When we read data from the websocket, we write it to the socket
            void handle_wsocket_read(
                const std::error_code& error,
                const size_t& bytes_transferred
            );

            // We wrote the data we got from the socket to the websocket, so
            // now we can read more data from the socket
            void handle_wsocket_write(const std::error_code& error);

            // Close the socket and the websocket
            void close();

            net::ip::tcp::socket socket_;
            wsstream wsocket_;

            static const int max_data_length = 8192; //8KB
            std::array<unsigned char, max_data_length> socket_data_;
            std::array<unsigned char, max_data_length> wsocket_data_;
    };
}

#endif /* BRIDGE_H_000F58BF269299 */
