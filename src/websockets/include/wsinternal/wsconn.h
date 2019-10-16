#include <iostream>
#include <memory>

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>

#include <wsinternal/uri.h>

namespace wsinternal {
    namespace beast = boost::beast;
    namespace net = boost::asio;

    typedef beast::websocket::stream<beast::ssl_stream<beast::tcp_stream>> wsstream;

    class wsconn : std::enable_shared_from_this<wsconn> {
            wsconn(
                net::io_context& io_context,
                net::ssl::context& ssl_context,
                std::string& uri,
                std::function<void(wsstream)> sockethandler
            ) :
                io_context_(io_context),
                ssl_context_(ssl_context),
                resolver_(net::make_strand(io_context_)),
                ws_(net::make_strand(io_context_), ssl_context_),
                uri_(uri),
                sockethandler_(sockethandler)
            {}

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
            void start() {
                auto [host, port, path] = parse_uri(uri_);
            }

            void on_connect(const std::error_code& error, net::ip::tcp::resolver::results_type::endpoint_type) {
                if (!error) {
                    // Set a timeout on the operation
                    beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

                    // Perform the SSL handshake
                    ws_.next_layer().async_handshake(
                        net::ssl::stream_base::client,
                        beast::bind_front_handler(
                            &wsconn::on_ssl_handshake,
                            shared_from_this()
                        )
                    );
                } else {
                    std::cerr << "Failed to connect: " << error.message() << std::endl;
                }
            }

            void on_ssl_handshake(const std::error_code& error) {
                if (!error) {
                    // Turn off the timeout on the tcp_stream, because
                    // the websocket stream has its own timeout system.
                    beast::get_lowest_layer(ws_).expires_never();

                    // Set suggested timeout settings for the websocket
                    ws_.set_option(
                        beast::websocket::stream_base::timeout::suggested(
                            beast::role_type::client)
                    );

                    // Set a decorator to change the User-Agent of the handshake
                    ws_.set_option(beast::websocket::stream_base::decorator(
                        [] (beast::websocket::request_type& req)
                        {
                            req.set(beast::http::field::user_agent,
                            "Oh noes... bad stuff is happening");
                        })
                    );

                    // Perform the websocket handshake
                    ws_.async_handshake("thebaddies.redrangerz.com", "/",
                        beast::bind_front_handler(
                            &wsconn::on_handshake,
                            shared_from_this()));
                } else {
                    std::cerr << "Failed to SSL handshake: " << error.message() << std::endl;
                }
            }

            void on_handshake(const std::error_code& error) {
                if (!error) {
                    // Hand off the websocket to the socket handler now that we
                    // are connected and up and running
                    sockethandler_(std::move(ws_));
                } else {
                    std::cerr << "Failed to websocket handshake: " << error.message() << std::endl;
                }
            }

            net::io_context& io_context_;
            net::ssl::context& ssl_context_;
            net::ip::tcp::resolver resolver_;
            wsstream ws_;
            std::string& uri_;
            std::function<void(wsstream)> sockethandler_;
    };
}
