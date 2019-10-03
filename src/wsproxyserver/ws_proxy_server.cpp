#include "ws_proxy_server.h"
#include "tcp_proxy.h"

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;


void ws_proxy::run() {
    // Start the server accept loop
    ws_server.start_accept();

    // Start the ASIO io_service run loop
    ws_server.run();
}

bool ws_proxy::is_SSH_server_up(){
    // First let check that SSH server is up
    asio::io_service io_service;
    asio::error_code err;
    asio::ip::tcp::socket socket(io_service);
    socket.connect(asio::ip::tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 22), err);

    if (err) {
        std::cout << "Error connecting to SSH on localhost. " << err.message() << "\n";
        return false;
    }
    socket.close();
    return true;
}

ws_proxy::ws_proxy()
{ 
    
}

void ws_proxy::on_message(server* s, websocketpp::connection_hdl hdl, message_ptr msg) {
    std::cout << "on_message called with hdl: " << hdl.lock().get()
              << " and message: " << msg->get_payload()
              << std::endl;

    asio::error_code error;

    void* shr_ptr_hdl = hdl.lock().get();


    server::connection_ptr con = s->get_con_from_hdl(hdl);
    con->get_socket();

    if (active_connections.count(shr_ptr_hdl) < 1) {
        // this should not happen

        //print error
        return;
    }

    asio::write(*active_connections[shr_ptr_hdl], asio::buffer(msg->get_payload()), error);

    if (error) {
        std::cout << "send failed: " << error.message() << std::endl;
    }   
}

/*Can put any fake site you want*/
void ws_proxy::on_http(server* s, websocketpp::connection_hdl hdl) {
    server::connection_ptr con = s->get_con_from_hdl(hdl);
    
    //con->set_body("Hello World!");
    //con->set_status(websocketpp::http::status_code::ok);
    con->set_status(websocketpp::http::status_code::im_a_teapot);
}

std::string get_password() {
    return "test";
}



ws_proxy::context_ptr ws_proxy::on_tls_init(tls_mode mode, websocketpp::connection_hdl hdl) {
    namespace asio = websocketpp::lib::asio;

    std::cout << "on_tls_init called with hdl: " << hdl.lock().get() << std::endl;
    std::cout << "using TLS mode: " << (mode == MOZILLA_MODERN ? "Mozilla Modern" : "Mozilla Intermediate") << std::endl;

    context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);

    try {
        if (mode == MOZILLA_MODERN) {
            // Modern disables TLSv1
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::no_tlsv1 |
                             asio::ssl::context::single_dh_use);
        } else {
            ctx->set_options(asio::ssl::context::default_workarounds |
                             asio::ssl::context::no_sslv2 |
                             asio::ssl::context::no_sslv3 |
                             asio::ssl::context::single_dh_use);
        }
        ctx->set_password_callback(bind(&get_password));


        ctx->use_certificate_chain_file("server.pem");
        ctx->use_private_key_file("server.pem", asio::ssl::context::pem);
        
        //ctx->use_certificate_chain_file("C:\\Users\\default.DESKTOP-Q4FDM2G\\Documents\\code\\websocketpp\\examples\\echo_server_tls\\server.pem");
        //ctx->use_private_key_file("C:\\Users\\default.DESKTOP-Q4FDM2G\\Documents\\code\\websocketpp\\examples\\echo_server_tls\\server.pem", asio::ssl::context::pem);
        
        // Example method of generating this file:
        // `openssl dhparam -out dh.pem 2048`
        // Mozilla Intermediate suggests 1024 as the minimum size to use
        // Mozilla Modern suggests 2048 as the minimum size to use.
        //ctx->use_tmp_dh_file("C:\\Users\\default.DESKTOP-Q4FDM2G\\Documents\\code\\websocketpp\\examples\\echo_server_tls\\dh.pem");
        ctx->use_tmp_dh_file("dh.pem");

        std::string ciphers;
        
        if (mode == MOZILLA_MODERN) {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";
        } else {
            ciphers = "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
        }
        
        if (SSL_CTX_set_cipher_list(ctx->native_handle() , ciphers.c_str()) != 1) {
            std::cout << "Error setting cipher list" << std::endl;
        }
    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    return ctx;
}

asio::error_code ws_proxy::connect_SSH_server(websocketpp::connection_hdl hdl){
    asio::io_service io_service;
    asio::error_code err;
    auto socket = std::make_shared <asio::ip::tcp::socket>(io_service);
    socket->connect(asio::ip::tcp::endpoint(asio::ip::address::from_string("127.0.0.1"), 22), err);

    if (err) {
        std::cout << "Error connecting to SSH on localhost. " << err.message() << "\n";
    }
    else {
        void* shr_ptr_hdl = hdl.lock().get();
        active_connections[shr_ptr_hdl] = socket;
    }

    return err;
}



void ws_proxy::read_handle(const asio::error_code& error, const size_t& bytes_transferred) {

}



void ws_proxy::init() {
    // Initialize ASIO
    ws_server.init_asio();

    // Register our message handler
    ws_server.set_user_agent("test");
    ws_server.set_message_handler(bind(&ws_proxy::on_message, shared_from_this(), &ws_server, ::_1, ::_2));
    ws_server.set_http_handler(bind(&ws_proxy::on_http, shared_from_this(), &ws_server, ::_1));
    ws_server.set_tls_init_handler(bind(&ws_proxy::on_tls_init, shared_from_this(), MOZILLA_INTERMEDIATE, ::_1));
    ws_server.set_close_handler(bind(&ws_proxy::on_close, shared_from_this(), &ws_server, ::_1));
    ws_server.set_open_handler(bind(&ws_proxy::on_open, shared_from_this(), &ws_server, ::_1));
    ws_server.set_validate_handler(bind(&ws_proxy::on_validate, shared_from_this(), &ws_server, ::_1));


    //ws_server.async_accept()

    /*ws_server.async_accept()


        ws_server.async_accept(new_session->m_socket,
            bind(&tcp_echo_server::handle_accept, this, new_session, _1));*/


    // Listen on port 9002
    ws_server.listen(4443);
}

/* This function will be run in a */
void ws_proxy::read_SSH(websocketpp::connection_hdl hdl) {
    auto socket = active_connections[hdl.lock().get()];
    asio::error_code error;
    std::size_t received_bytes;

    auto self = shared_from_this();
    auto buffer = std::make_shared<std::vector<std::uint8_t>>(1024, 0);
    

    socket->async_read_some(
        asio::buffer(*buffer, buffer->size()),
        bind(&ws_proxy::read_handle, this, std::placeholders::_1, std::placeholders::_2));

    if (error && error != asio::error::eof) {
        std::cout << "receive failed: " << error.message() << std::endl;
    }
    else {
        /*const char* data = asio::buffer_cast<const char*>(receive_buffer.data());
        std::cout << data << std::endl;*/
    }


}

void ws_proxy::handle_downstream_read(const asio::error_code& error,
    const size_t& bytes_transferred)
{
   
}

/* This function will validate that the expected */
bool ws_proxy::on_validate(server* s, websocketpp::connection_hdl hdl) {
    server::connection_ptr con = s->get_con_from_hdl(hdl);
    if (con->get_request_header("User-Agent") != accepted_UA) {
        con->set_status(websocketpp::http::status_code::forbidden);
        return false;
    }
    return true;
}

/* In this function we connect to the */
void ws_proxy::on_open(server* s, websocketpp::connection_hdl hdl) {
    server::connection_ptr con = s->get_con_from_hdl(hdl);
    if (con->get_request_header("User-Agent") != "My custom UA") {
        // Error
    }
    return;
    //server::connection_ptr con = s->get_con_from_hdl(hdl);
    //auto acceptor = std::make_shared<tcp_proxy::bridge::acceptor>(con->get_raw_socket().get_io_service());
    ////tcp_proxy::bridge::acceptor acceptor(con->get_raw_socket().get_io_service()); // 127.0.0.1 22

    //acceptor->accept_connections();
    //active_connections2[hdl.lock().get()] = acceptor;

    //return;
    //server::connection_ptr con = s->get_con_from_hdl(hdl);

    //con->get_raw_socket().get_io_service() == s->get_io_service();


    auto err = connect_SSH_server(hdl);
    if (err) {
        return;
    }


    auto socket = active_connections[hdl.lock().get()];
    asio::error_code error;
    std::size_t received_bytes;

    auto self = shared_from_this();
    //auto buffer = std::make_shared<std::vector<std::uint8_t>>(1024, 0);


   /* socket->async_read_some(
        asio::buffer(downstream_data_, max_data_length),
        bind(&ws_proxy::read_handle, shared_from_this(), error, std::placeholders::_1, downstream_data_));
*/
    if (error && error != asio::error::eof) {
        std::cout << "receive failed: " << error.message() << std::endl;
    }
    else {
        /*const char* data = asio::buffer_cast<const char*>(receive_buffer.data());
        std::cout << data << std::endl;*/
    }

    // If we connected correctly we create a thread that will be in 
    // charge of reading from the socket when there is data available
    
    //std::thread thread(&ws_proxy::read_SSH, shared_from_this(), hdl);
    
}

void ws_proxy::on_close(server* s, websocketpp::connection_hdl hdl) {
    void* shr_ptr_hdl = hdl.lock().get();
    if (active_connections.find(shr_ptr_hdl) != active_connections.end()) {
        // ToDo: stop the reading tread
        active_connections.erase(shr_ptr_hdl);
    }
}

int main() {
    auto ws_server = std::make_shared<ws_proxy>();
    ws_server->init();
    /*if (ws_server->is_SSH_server_up() == false) {
        return 1;
    }*/

    ws_server->run();

   /* std::thread cthread(&ws_proxy::run, *ws_server);


    cthread.detach();*/
}
