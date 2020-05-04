#include <iostream>
#include <memory>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

#include <wsinternal/uri.h>
#include <wsinternal/wsconn.h>

#ifndef WEBSOCKETS_COOKIE_NAME
#define WEBSOCKETS_COOKIE_NAME "c"
#endif

#ifndef WEBSOCKETS_COOKIE_VALUE
#define WEBSOCKETS_COOKIE_VALUE "unknown"
#endif

std::string _cookie = std::string(WEBSOCKETS_COOKIE_NAME) + "=" + std::string(WEBSOCKETS_COOKIE_VALUE);

namespace wsinternal {
namespace beast = boost::beast;
namespace net = boost::asio;

wsconn::wsconn(
    net::executor executor,
    net::ip::tcp::socket&& socket,
    net::ssl::context& ssl_context,
    std::function<void(wsstream&&)> sockethandler)
    : executor_(executor)
    , ssl_context_(ssl_context)
    , resolver_(net::make_strand(executor_))
    , ws_(beast::tcp_stream(std::move(socket)), ssl_context_)
    , sockethandler_(sockethandler)
{
    ws_.binary(true);
}

void wsconn::start()
{
    // Set a timeout on the operation
    beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

    // Perform the SSL handshake
    ws_.next_layer().async_handshake(
        net::ssl::stream_base::client,
        beast::bind_front_handler(
            &wsconn::on_ssl_handshake,
            shared_from_this()));
}

void wsconn::on_ssl_handshake(const std::error_code& error)
{
    if (!error) {
        // Turn off the timeout on the tcp_stream, because
        // the websocket stream has its own timeout system.
        beast::get_lowest_layer(ws_).expires_never();

        // Set suggested timeout settings for the websocket
        ws_.set_option(
            beast::websocket::stream_base::timeout::suggested(
                beast::role_type::client));

        // Set a decorator to change the User-Agent of the handshake
        ws_.set_option(beast::websocket::stream_base::decorator(
            [](beast::websocket::request_type& req) {
                req.set(beast::http::field::user_agent,
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 "
                    "Safari/537.36");
                req.set(
                    beast::http::field::set_cookie,
                    _cookie);
            }));

        // Perform the websocket handshake
        ws_.async_handshake("thebaddies.redrangerz.com", "/",
            beast::bind_front_handler(
                &wsconn::on_handshake,
                shared_from_this()));
    } else {
        std::cerr << "Failed to SSL handshake: " << error.message() << std::endl;
    }
}

void wsconn::on_handshake(const std::error_code& error)
{
    if (!error) {
        // Hand off the websocket to the socket handler now that we
        // are connected and up and running
        sockethandler_(std::move(ws_));
    } else {
        std::cerr << "Failed to websocket handshake: " << error.message() << std::endl;
    }
}
} // namespace wsinternal
