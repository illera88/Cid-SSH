#include <wsinternal/bridge.h>

namespace wsinternal {

#ifndef NDEBUG
    template <typename T>
    void debug_print(T this_, const std::string& function) {
        std::cerr << "[" << this_ << "] " << function << std::endl;
    }
#else
    template <typename T>
    void debug_print(T this_, const std::string& function) {}
#endif

    namespace beast = boost::beast;
    namespace net = boost::asio;

    typedef beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>> wsstream;

    bridge::bridge(net::ip::tcp::socket&& socket, wsstream&& wsocket)
        : socket_(std::move(socket)), wsocket_(std::move(wsocket))
    {}

    void bridge::start() {
        debug_print(this, "start");

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
        wsocket_.async_read_some(
            net::buffer(wsocket_data_, max_data_length),
            std::bind(
                &bridge::handle_wsocket_read,
                shared_from_this(),
                std::placeholders::_1,
                std::placeholders::_2
            )
        );
    }

    // When we read data from the socket, we write it to the websocket
    void bridge::handle_socket_read(
        const std::error_code& error,
        const size_t& bytes_transferred
    ) {
        debug_print(this, "handle_socket_read");

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
    void bridge::handle_socket_write(const std::error_code& error) {
        debug_print(this, "handle_socket_write");

        if (!error) {
            wsocket_.async_read_some(
                net::buffer(wsocket_data_, max_data_length),
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
    void bridge::handle_wsocket_read(
        const std::error_code& error,
        const size_t& bytes_transferred
    ) {
        debug_print(this, "handle_wsocket_read");

        if (!error) {
            async_write(socket_,
                net::buffer(wsocket_data_, bytes_transferred),
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
    void bridge::handle_wsocket_write(const std::error_code& error) {
        debug_print(this, "handle_wsocket_write");

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

    void bridge::close() {
        debug_print(this, "close");

        if (socket_.is_open()) {
            socket_.close();
        }

        if (wsocket_.is_open()) {
            wsocket_.close(beast::websocket::close_code::normal);
        }
    }
}
