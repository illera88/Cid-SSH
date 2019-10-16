#include <iostream>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>

namespace wsinternal {
    namespace beast = boost::beast;
    namespace net = boost::asio;

    typedef beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>> wsstream;

    class bridge : public std::enable_shared_from_this<bridge> {
            // Private constructor, use create()
            bridge(net::ip::tcp::socket socket, wsstream wsocket)
                : socket_(std::move(socket)), wsocket_(std::move(wsocket))
            {}

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
            void start() {
                // Setup reading from the TCP/IP socket
                socket_.async_read_some(
                    net::buffer(socket_data_, max_data_length),
                    std::bind(
                        &bridge::handle_socket_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2
                    )
                );

                // Setup reading from the Websocket
                wsocket_.async_read_some(net::buffer(wsocket_data_, max_data_length),
                    std::bind(
                        &bridge::handle_wsocket_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2
                    )
                );
            }

            // When we read data from the socket, we write it to the websocket
            void handle_socket_read(
                const std::error_code& error,
                const size_t& bytes_transferred
            ) {
                if (!error) {
                    wsocket_.async_write(
                        net::buffer(socket_data_, bytes_transferred),
                        std::bind(
                            &bridge::handle_wsocket_write,
                            shared_from_this(),
                            std::placeholders::_1
                        )
                    );
                } else {
                    close();
                }
            }

            // We wrote the data we got from the websocket to the socket, so
            // now we can read more data from the websocket
            void handle_socket_write(const std::error_code& error) {
                if (!error) {
                    wsocket_.async_read_some(net::buffer(wsocket_data_, max_data_length),
                        std::bind(
                            &bridge::handle_wsocket_read,
                            shared_from_this(),
                            std::placeholders::_1,
                            std::placeholders::_2
                        )
                    );
                } else {
                    close();
                }
            }

            // When we read data from the websocket, we write it to the socket
            void handle_wsocket_read(
                const std::error_code& error,
                const size_t& bytes_transferred
            ) {
                if (!error) {
                    async_write(socket_,
                        net::buffer(socket_data_, bytes_transferred),
                        std::bind(
                            &bridge::handle_socket_write,
                            shared_from_this(),
                            std::placeholders::_1
                        )
                    );
                } else {
                    close();
                }
            }

            // We wrote the data we got from the socket to the websocket, so
            // now we can read more data from the socket
            void handle_wsocket_write(const std::error_code& error) {
                if (!error) {
                    socket_.async_read_some(
                        net::buffer(socket_data_, max_data_length),
                        std::bind(
                            &bridge::handle_socket_read,
                            shared_from_this(),
                            std::placeholders::_1,
                            std::placeholders::_2
                        )
                    );
                } else {
                    close();
                }
            }

            void close() {
                if (socket_.is_open()) {
                    socket_.close();
                }

                if (wsocket_.is_open()) {
                    wsocket_.close(beast::websocket::close_code::normal);
                }
            }

            net::ip::tcp::socket socket_;
            wsstream wsocket_;

            static const int max_data_length = 8192; //8KB
            std::array<unsigned char, max_data_length> socket_data_;
            std::array<unsigned char, max_data_length> wsocket_data_;
    };
}
