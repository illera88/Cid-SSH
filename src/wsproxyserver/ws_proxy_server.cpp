#include <wsinternal/bridge.h>

#include "ws_proxy_server.h"

namespace internal {
   class connector: public std::enable_shared_from_this<connector> {
            connector(
                asio::io_context& io_context,
                const asio::ip::address& ssh_host,
                unsigned short ssh_port,
                std::function<void(asio::ip::tcp::socket)> sockethandler
            ) :
                io_context_(io_context),
                socket_(io_context_),
                ssh_address_(ssh_host),
                ssh_port_(ssh_port),
                sockethandler_(sockethandler)
            {}

        public:
            // Ah, C++ templating can be such a joy
            template<typename ... T>
            static std::shared_ptr<connector> create(T&& ... all) {
                // Can't use make_shared here because of visibility rules and
                // all that fun jazz...
                auto ptr = std::shared_ptr<connector>(new connector(std::forward<T>(all)...));
                ptr->start();
                return ptr;
            }

        private:
            void start() {
                socket_.async_connect(
                    asio::ip::tcp::endpoint(ssh_address_, ssh_port_),
                    std::bind(
                        &connector::handle_connect,
                        shared_from_this(),
                        std::placeholders::_1
                    )
                );
            }

            void handle_connect(const asio::error_code& error) {
                if (!error) {
                    sockethandler_(std::move(socket_));
                    std::cout << "Connected to SSH server" << std::endl;
                } else {
                    std::cerr << "Failed to connect to SSH server" << std::endl;
                }
            }

            asio::io_context& io_context_;
            asio::ip::tcp::socket socket_;
            asio::ip::address ssh_address_;
            unsigned short ssh_port_;
            std::function<void(asio::ip::tcp::socket)> sockethandler_;
    };
}

ws_proxy::ws_proxy(std::string& ssh_address, unsigned short ssh_port) :
    ssh_address_(asio::ip::address::from_string(ssh_address)),
    ssh_port_(ssh_port),
    aio_work_(std::make_shared<asio::io_context::work>(io_context_)),
    io_runner_(
        std::thread(
            [&] {
                // Start up the asio context in a thread, forever
                io_context_.run();
            }
        )
    )
{
    // Initialize ASIO
    ws_server.init_asio(&io_context_);

    // Register our message handler
    ws_server.set_user_agent("test");
    ws_server.set_http_handler(std::bind(&ws_proxy::on_http, this, std::placeholders::_1));
    ws_server.set_tls_init_handler(std::bind(&ws_proxy::on_tls_init, this, MOZILLA_INTERMEDIATE, std::placeholders::_1));
    ws_server.set_open_handler(std::bind(&ws_proxy::on_open, this, std::placeholders::_1));
    ws_server.set_validate_handler(std::bind(&ws_proxy::on_validate, this, std::placeholders::_1));

    // Listen on port 9002
    ws_server.listen(4443);
    ws_server.start_accept();
}

ws_proxy::~ws_proxy() {
    // Let asio know it's time for a nap
    aio_work_.reset();

    // Now we wait on the thread to finish what its doing
    io_runner_.join();
}

/*Can put any fake site you want*/
void ws_proxy::on_http(websocketpp::connection_hdl hdl) {
    server::connection_ptr con = ws_server.get_con_from_hdl(hdl);

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

/* This function will validate that the expected */
bool ws_proxy::on_validate( websocketpp::connection_hdl hdl) {
    server::connection_ptr con = ws_server.get_con_from_hdl(hdl);

    if (con->get_request_header("User-Agent") != accepted_UA) {
        con->set_status(websocketpp::http::status_code::forbidden);
        return false;
    }
    return true;
}

/* In this function we connect to the */
void ws_proxy::on_open(websocketpp::connection_hdl hdl) {
    server::connection_ptr con = ws_server.get_con_from_hdl(hdl);

    // Pause reading from the websocket until we are ready
    auto ec = con->pause_reading();
    if (ec) {
        throw websocketpp::exception(ec.message());
    }

    internal::connector::create(
        io_context_,
        ssh_address_,
        ssh_port_,
        [con] (asio::ip::tcp::socket socket) {
            // Start reading from websockets again
            con->resume_reading();

            // Hand off this sokcet and websocket to the bridge
            auto bridge = internal::bridge<server::connection_ptr>::create(std::move(socket), std::move(con));
        }
    );
}

void ws_proxy::run_forever() {
    io_runner_.join();
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <SSH server IP> <SSH server port>" << std::endl;
        return -1;
    }

    std::string ssh_address = argv[1];
    auto ssh_port = static_cast<unsigned short>(std::stoul(argv[2]));

    ws_proxy ws_server(ssh_address, ssh_port);
    ws_server.run_forever();
}
