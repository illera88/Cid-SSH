#pragma once

#define ASIO_STANDALONE
#define _WEBSOCKETPP_CPP11_INTERNAL_

#include <websocketpp/config/asio.hpp>

#include <websocketpp/server.hpp>
#include <iostream>
#include <map>

#include "tcp_proxy.h"

class ws_proxy : public std::enable_shared_from_this<ws_proxy>
{
    // pull out the type of messages sent by our config
    typedef websocketpp::config::asio::message_type::ptr message_ptr;
    typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
    
    typedef std::shared_ptr<ws_proxy> ptr_type;

    // See https://wiki.mozilla.org/Security/Server_Side_TLS for more details about
    // the TLS modes. The code below demonstrates how to implement both the modern
    enum tls_mode {
        MOZILLA_INTERMEDIATE = 1,
        MOZILLA_MODERN = 2
    };
public:
    ws_proxy();
    bool is_SSH_server_up();
    void run();
    static std::shared_ptr<ws_proxy> create() { return std::make_shared<ws_proxy>(); }
    void init();
    typedef websocketpp::server<websocketpp::config::asio_tls> server;

private:
    server ws_server;
    std::string accepted_UA = "Acepted UA";
    std::map<void*, std::shared_ptr<asio::ip::tcp::socket>> active_connections;
    std::map<void*, std::shared_ptr<tcp_proxy::bridge::acceptor>> active_connections2;
    //std::shared_ptr<tcp_proxy::bridge> _session;
    void on_message(server* s, websocketpp::connection_hdl hdl, message_ptr msg);
    void on_http(server* s, websocketpp::connection_hdl hdl);
    ws_proxy::context_ptr on_tls_init(tls_mode mode, websocketpp::connection_hdl hdl);
    asio::error_code connect_SSH_server(websocketpp::connection_hdl hdl);
    void read_handle(const asio::error_code& error, const size_t& bytes_transferred);
    
    void read_SSH(websocketpp::connection_hdl hdl);
    void handle_downstream_read(const asio::error_code& error, const size_t& bytes_transferred);
    bool on_validate(server* s, websocketpp::connection_hdl hdl);
    void on_open(server* s, websocketpp::connection_hdl hdl);
    void on_close(server* s, websocketpp::connection_hdl hdl);



    enum { max_data_length = 8192 }; //8KB
    unsigned char downstream_data_[max_data_length] = { 0 };
    unsigned char upstream_data_[max_data_length] = { 0 };



};
