#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <filesystem>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/make_unique.hpp>

#include <wsinternal/acceptor.h>
#include <wsinternal/bridge.h>

namespace beast = boost::beast; // from <boost/beast.hpp>
namespace http = beast::http; // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace net = boost::asio; // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

namespace wsinternal {
class shared_storage {
public:
    shared_storage(wsstream&& wsocket)
        : wsocket_(std::move(wsocket))
    {
    }

    wsstream get_wsocket()
    {
        return std::move(wsocket_);
    }

private:
    wsstream wsocket_;
};

class connector : public std::enable_shared_from_this<connector> {
    connector(
        net::executor executor,
        const net::ip::address& ssh_host,
        unsigned short ssh_port,
        std::function<void(net::ip::tcp::socket)> sockethandler)
        : socket_(executor)
        , ssh_address_(ssh_host)
        , ssh_port_(ssh_port)
        , sockethandler_(sockethandler)
    {
    }

public:
    // Ah, C++ templating can be such a joy
    template <typename... T>
    static std::shared_ptr<connector> create(T&&... all)
    {
        // Can't use make_shared here because of visibility rules and
        // all that fun jazz...
        auto ptr = std::shared_ptr<connector>(new connector(std::forward<T>(all)...));
        ptr->start();
        return ptr;
    }

private:
    void start()
    {
        socket_.async_connect(
            net::ip::tcp::endpoint(ssh_address_, ssh_port_),
            std::bind(
                &connector::handle_connect,
                shared_from_this(),
                std::placeholders::_1));
    }

    void handle_connect(const std::error_code& error)
    {
        if (!error) {
            sockethandler_(std::move(socket_));
            std::cout << "Connected to SSH server" << std::endl;
        } else {
            std::cerr << "Failed to connect to SSH server" << std::endl;
        }
    }

    net::ip::tcp::socket socket_;
    net::ip::address ssh_address_;
    unsigned short ssh_port_;
    std::function<void(net::ip::tcp::socket)> sockethandler_;
};
} // namespace wsinternal

//------------------------------------------------------------------------------

// Report a failure
void fail(beast::error_code ec, char const* what)
{
    // ssl::error::stream_truncated, also known as an SSL "short read",
    // indicates the peer closed the connection without performing the
    // required closing handshake (for example, Google does this to
    // improve performance). Generally this can be a security issue,
    // but if your communication protocol is self-terminated (as
    // it is with both HTTP and WebSocket) then you may simply
    // ignore the lack of close_notify.
    //
    // https://github.com/boostorg/beast/issues/38
    //
    // https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
    //
    // When a short read would cut off the end of an HTTP message,
    // Beast returns the error beast::http::error::partial_message.
    // Therefore, if we see a short read here, it has occurred
    // after the message has been completed, so it is safe to ignore it.

    if (ec == net::ssl::error::stream_truncated)
        return;

    std::cerr << what << ": " << ec.message() << "\n";
}

//------------------------------------------------------------------------------

// Echoes back all received WebSocket messages.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
class websocket_session : public std::enable_shared_from_this<websocket_session> {
private:
    // Create the ssl_websocket_session
    websocket_session(beast::ssl_stream<beast::tcp_stream>&& stream, const std::string& ssh_server, const int& ssh_port)
        : ws_(std::move(stream))
        , ssh_server_(ssh_server)
        , ssh_port_(ssh_port)
    {
    }

public:
    // Ah, C++ templating can be such a joy
    template <class Body, class Allocator, typename... T>
    static auto create(http::request<Body, http::basic_fields<Allocator>> req, T&&... all)
    {
        // Can't use make_shared here because of visibility rules and
        // all that fun jazz...
        auto ptr = std::shared_ptr<websocket_session>(
            new websocket_session(std::forward<T>(all)...));
        ptr->do_accept(req);
        return ptr;
    }

private:
    // Start the asynchronous operation
    template <class Body, class Allocator>
    void do_accept(http::request<Body, http::basic_fields<Allocator>> req)
    {
        // Set suggested timeout settings for the websocket
        ws_.set_option(
            websocket::stream_base::timeout::suggested(beast::role_type::server));

        // Set a decorator to change the Server of the handshake
        ws_.set_option(
            websocket::stream_base::decorator([](websocket::response_type& res) {
                res.set(http::field::server, "Teapot/1.0");
            }));

        // Accept the websocket handshake
        ws_.async_accept(
            req, beast::bind_front_handler(&websocket_session::on_accept, shared_from_this()));
    }

    void on_accept(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "accept");

        auto executor = ws_.get_executor();
        auto storage = std::make_shared<wsinternal::shared_storage>(std::move(ws_));
        auto connector = wsinternal::connector::create(
            std::move(executor),
            net::ip::address::from_string(ssh_server_), ssh_port_,
            [storage](net::ip::tcp::socket&& socket) {
                auto bridge = wsinternal::bridge::create(std::move(socket), std::move(storage->get_wsocket()));
            });
    }

    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws_;
    beast::flat_buffer buffer_;
    const std::string& ssh_server_;
    const int& ssh_port_;
};

//------------------------------------------------------------------------------

// Handles an SSL HTTP connection
class http_session : public std::enable_shared_from_this<http_session> {
    typedef std::function<void(
        beast::ssl_stream<beast::tcp_stream>&&,
        http::request_parser<http::string_body>&&)>
        on_upgrade_func;

private:
    // Create the http_session
    http_session(
        beast::tcp_stream&& stream,
        ssl::context& ctx,
        on_upgrade_func on_upgrade)
        : stream_(std::move(stream), ctx)
        , on_upgrade_(on_upgrade)
    {
    }

public:
    // Ah, C++ templating can be such a joy
    template <typename... T>
    static auto create(T&&... all)
    {
        // Can't use make_shared here because of visibility rules and
        // all that fun jazz...
        auto ptr = std::shared_ptr<http_session>(
            new http_session(std::forward<T>(all)...));
        ptr->start();
        return ptr;
    }

private:
    // Start the session
    void start()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL handshake
        stream_.async_handshake(
            ssl::stream_base::server,
            beast::bind_front_handler(&http_session::on_handshake,
                shared_from_this()));
    }

    void do_read()
    {
        // Construct a new parser for each message
        parser_.emplace();

        // Apply a reasonable limit to the allowed size
        // of the body in bytes to prevent abuse.
        parser_->body_limit(10000);

        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Read a request using the parser-oriented interface
        http::async_read(
            stream_, buffer_, *parser_,
            beast::bind_front_handler(&http_session::on_read, shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        // This means they closed the connection
        if (ec == http::error::end_of_stream)
            return do_eof();

        if (ec)
            return fail(ec, "read");

        // See if it is a WebSocket Upgrade
        if (websocket::is_upgrade(parser_->get())) {
            // Disable the timeout.
            // The websocket::stream uses its own timeout settings.
            beast::get_lowest_layer(stream_).expires_never();

            // Create a websocket session, transferring ownership
            // of both the socket and the HTTP request.
            on_upgrade_(std::move(stream_), std::move(parser_.value()));
            return;
        }

        auto req = parser_->release();

        res = http::response<http::string_body> {};
        res.version(req.version());
        res.reason("I'm a teapot");
        res.result(418);
        res.set(http::field::server, "Teapot/1.0");
        res.set(http::field::content_type, "text/plain");
        res.set(http::field::connection, "close");
        res.keep_alive(false);
        res.body() = "Tea pot is not yet ready.\r\n";
        res.prepare_payload();

        // We are always a teapot that is not ready
        http::async_write(stream_, res,
            beast::bind_front_handler(&http_session::on_write,
                shared_from_this(),
                res.need_eof()));
    }

    void on_write(bool close, beast::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        if (ec)
            return fail(ec, "write");

        if (close) {
            // This means we should close the connection, usually because
            // the response indicated the "Connection: close" semantic.
            return do_eof();
        }

        do_read();
    }

    // Called by the base class
    void do_eof()
    {
        // Set the timeout.
        beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));

        // Perform the SSL shutdown
        stream_.async_shutdown(beast::bind_front_handler(&http_session::on_shutdown,
            shared_from_this()));
    }

    void on_handshake(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "handshake");

        do_read();
    }

    void on_shutdown(beast::error_code ec)
    {
        if (ec)
            return fail(ec, "shutdown");

        // At this point the connection is closed gracefully
    }

    // The parser is stored in an optional container so we can
    // construct it from scratch it at the beginning of each new message.
    beast::ssl_stream<beast::tcp_stream> stream_;
    on_upgrade_func on_upgrade_;
    std::optional<http::request_parser<http::string_body>> parser_;
    http::response<http::string_body> res;
    beast::flat_buffer buffer_;
};

//------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    auto const filename = std::filesystem::path(argv[0]).filename().string();
    // Check command line arguments.
    if (argc != 6) {
        std::cerr << "Usage: " << filename << " <address> <port> <sshd ip> <sshd port> <pem certificate file>\n"
                  << "Example:\n"
                  << "    " << filename <<" 0.0.0.0 8080 127.0.0.1 22 server.pem\n"
                  << "To generate cert file do:\n" 
                  << "     openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const ssh_server = std::string(argv[3]);
    auto const ssh_port = std::atoi(argv[4]);

    auto threads = 1;

    // The io_context is required for all I/O
    net::io_context ioc { threads };

    // The SSL context is required, and holds certificates
    ssl::context ctx { ssl::context::tlsv12 };

    //// This holds the self-signed certificate used by the server
    //ctx.set_password_callback(
    //    [](std::size_t max_length, net::ssl::context::password_purpose purpose) {
    //        return std::string("test");
    //    });
    ctx.use_certificate_chain_file(argv[5]);
    ctx.use_private_key_file(argv[5], net::ssl::context::pem);

    auto acceptor = wsinternal::acceptor {
        ioc.get_executor(), tcp::endpoint { address, port }, [&](net::ip::tcp::socket&& socket) {
            http_session::create(
                beast::tcp_stream(std::move(socket)),
                ctx,
                [&ssh_server, &ssh_port](beast::ssl_stream<beast::tcp_stream>&& stream,
                    http::request_parser<http::string_body>&& parser) {
                    websocket_session::create(parser.release(), std::move(stream), ssh_server, ssh_port);
                });
        }
    };

    acceptor.accept_connections();

    // Capture SIGINT and SIGTERM to perform a clean shutdown
    net::signal_set signals(ioc, SIGINT, SIGTERM);
    signals.async_wait([&](beast::error_code const&, int) {
        // Stop the `io_context`. This will cause `run()`
        // to return immediately, eventually destroying the
        // `io_context` and all of the sockets in it.
        ioc.stop();
    });

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    // (If we get here, it means we got a SIGINT or SIGTERM)

    // Block until all the threads exit
    for (auto& t : v)
        t.join();

    return EXIT_SUCCESS;
}
