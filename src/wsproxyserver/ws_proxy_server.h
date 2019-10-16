#ifndef WS_PROXY_SERVER_H_6E710ED1791262
#define WS_PROXY_SERVER_H_6E710ED1791262

#include <iostream>
#include <map>

#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>

class ws_proxy {
    // pull out the type of messages sent by our config
    typedef websocketpp::config::asio::message_type::ptr message_ptr;
    typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
    
    // See https://wiki.mozilla.org/Security/Server_Side_TLS for more details about
    // the TLS modes. The code below demonstrates how to implement both the modern
    enum tls_mode {
        MOZILLA_INTERMEDIATE = 1,
        MOZILLA_MODERN = 2
    };
public:
    ws_proxy(std::string& ssh_address, unsigned short ssh_port);
    ~ws_proxy();
    typedef websocketpp::server<websocketpp::config::asio_tls> server;

    void run_forever();

private:
    server ws_server;
    std::string accepted_UA = "Acepted UA";
    void on_http(websocketpp::connection_hdl hdl);
    context_ptr on_tls_init(tls_mode mode, websocketpp::connection_hdl hdl);
    bool on_validate(websocketpp::connection_hdl hdl);
    void on_open(websocketpp::connection_hdl hdl);

    asio::ip::address ssh_address_;
    unsigned short ssh_port_;

    asio::io_service io_context_;
    std::shared_ptr<asio::io_service::work> aio_work_;
    std::thread io_runner_;
};

#endif /* WS_PROXY_SERVER_H_6E710ED1791262 */
