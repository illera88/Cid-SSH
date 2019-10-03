#include <iostream>
#include <stdexcept>
#include <thread>

#include <websocketswrapper.h>
#include <wsinternal/bridge.h>

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif

#include <asio.hpp>
#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>

namespace wswrap {
    typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
    typedef websocketpp::client<websocketpp::config::asio_tls_client> client;

    class websocket {
        public:
            websocket(asio::io_service& io_service, std::string uri) :
            io_service_(io_service), uri_(uri) {
                try {
                    // Set logging to be pretty verbose (everything except message payloads)
                    wsclient_.set_access_channels(websocketpp::log::alevel::all);
                    wsclient_.clear_access_channels(websocketpp::log::alevel::frame_payload);
                    wsclient_.set_error_channels(websocketpp::log::elevel::all);
                    wsclient_.set_user_agent("test11111111"); // ToDo: Set to something unique that the server will verify to prevent outsiders poking with our ssh server

                    // Initialize ASIO
                    wsclient_.init_asio(&io_service_);
                    wsclient_.set_tls_init_handler(std::bind(&websocket::on_tls_init, this, std::placeholders::_1));
                }
                catch (websocketpp::exception const& e) {
                    std::cout << e.what() << std::endl;
                }

            }

            // Caller is responsible for this connection
            client::connection_ptr new_connection() {
                websocketpp::lib::error_code ec;
                auto conn = wsclient_.get_connection(uri_, ec);

                if (ec) {
                    std::cerr << "Unable to create new websocket connection: " << ec.message() << std::endl;
                    throw std::runtime_error(std::string("Unable to create new websocket connection"));
                }

                wsclient_.connect(conn);

                return conn;
            };

        private:
            asio::io_service& io_service_;
            std::string uri_;
            wswrap::client wsclient_;

            context_ptr on_tls_init(websocketpp::connection_hdl) {
                try {
                    context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::method::tlsv12_client);
                    ctx->set_options(
                        asio::ssl::context::no_sslv2 |
                        asio::ssl::context::no_sslv3 |
                        asio::ssl::context::no_tlsv1 |
                        asio::ssl::context::no_tlsv1_1 |
                        asio::ssl::context::single_dh_use);
                    // Dangerous
                    ctx->set_verify_mode(asio::ssl::verify_none);
                    return ctx;
                } catch (std::exception &e) {
                    std::cerr << "Error setting up the SSL context: " << e.what() << std::endl;
                    throw;
                }
            }
    };
}

namespace internal {
    class acceptor {
        public:
            acceptor(
                asio::io_service& io_service,
                const asio::ip::address_v4& local_host,
                unsigned short local_port,
                std::function<void(asio::ip::tcp::socket)> sockethandler
            ) :
                io_service_(io_service),
                socket_(io_service_),
                localhost_address(local_host),
                acceptor_(
                    io_service_,
                    asio::ip::tcp::endpoint(
                        localhost_address,
                        local_port
                    )
                ),
                sockethandler_(sockethandler)
            {}

            asio::ip::tcp::endpoint local_endpoint() {
                return acceptor_.local_endpoint();
            }

            bool accept_connections()
            {
                try
                {
                    acceptor_.async_accept(socket_,
                        std::bind(&acceptor::handle_accept,
                            this,
                            std::placeholders::_1));
                }
                catch (std::exception& e)
                {
                    std::cerr << "Unable to start accepting connections: " << e.what() << std::endl;
                    return false;
                }

                return true;
            }

        private:

            void handle_accept(const asio::error_code& error)
            {
                if (!error)
                {
                    sockethandler_(std::move(socket_));

                    if (!accept_connections())
                    {
                        std::cerr << "Accepted connection, and now can't accept more!" << std::endl;
                    }
                }
                else
                {
                    std::cerr << "Error: " << error.message() << std::endl;
                }
            }

            asio::io_service& io_service_;
            asio::ip::tcp::socket socket_;
            asio::ip::address_v4 localhost_address;
            asio::ip::tcp::acceptor acceptor_;
            std::function<void(asio::ip::tcp::socket)> sockethandler_;
    };
}

WebsocketsWrapper::WebsocketsWrapper(std::string c2_uri) :
    pimpl_(std::make_unique<WebsocketsWrapper::impl>(c2_uri))
{}

WebsocketsWrapper::~WebsocketsWrapper() {

}

class WebsocketsWrapper::impl {
    public:
        impl(std::string& c2_uri) :
            uri_(c2_uri),
            aio_work_(std::make_shared<asio::io_service::work>(aio_context_)),
            io_runner_(
                    std::thread(
                        [&] {
                            // Start up the asio context in a thread, forever
                            aio_context_.run();
                        }
                    )
            ),
            acceptor_(
                aio_context_,
                asio::ip::address_v4::loopback(),
                0,
                [&] (asio::ip::tcp::socket socket) {
                    auto websocket_connection = websocket_.new_connection();
                    auto bridge = internal::bridge<wswrap::client::connection_ptr>::create(std::move(socket), std::move(websocket_connection));
                }
            ),
            websocket_(aio_context_, uri_)
        {
            acceptor_.accept_connections();

            // Get the local information and store it upon creation
            auto local_info = acceptor_.local_endpoint();
            local_ip_ = local_info.address().to_string();
            local_port_ = local_info.port();
        }

        ~impl() {
            // Let asio know it's time for a nap
            aio_work_.reset();

            // Now we wait on the thread to finish what its doing
            io_runner_.join();
        }

    private:
        std::string uri_;
        asio::io_context aio_context_;
        std::shared_ptr<asio::io_service::work> aio_work_;
        std::thread io_runner_;
        internal::acceptor acceptor_;
        wswrap::websocket websocket_;

    public:
        std::string local_ip_;
        unsigned int local_port_;
};

std::string& WebsocketsWrapper::local_ip() {
    return pimpl_->local_ip_;
}

unsigned int WebsocketsWrapper::local_port() {
    return pimpl_->local_port_;
}
