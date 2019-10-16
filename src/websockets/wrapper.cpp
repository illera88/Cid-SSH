#include <iostream>
#include <stdexcept>
#include <thread>

#include <websocketswrapper.h>
#include <wsinternal/bridge.h>


namespace internal {
    class acceptor {
        public:
            acceptor(
                asio::io_context& io_context,
                const asio::ip::address_v4& local_host,
                unsigned short local_port,
                std::function<void(asio::ip::tcp::socket)> sockethandler
            ) :
                io_context_(io_context),
                socket_(io_context_),
                localhost_address(local_host),
                acceptor_(
                    io_context_,
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

            asio::io_context& io_context_;
            asio::ip::tcp::socket socket_;
            asio::ip::address localhost_address;
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
            aio_work_(std::make_shared<asio::io_context::work>(io_context_)),
            io_runner_(
                    std::thread(
                        [&] {
                            // Start up the asio context in a thread, forever
                            io_context_.run();
                        }
                    )
            ),
            acceptor_(
                io_context_,
                asio::ip::address_v4::loopback(),
                0,
                [&] (asio::ip::tcp::socket socket) {
                    auto bridge = internal::bridge<wswrap::client::connection_ptr>::create(std::move(socket), std::move(websocket_connection));
                }
            ),
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
        asio::io_context io_context_;
        std::shared_ptr<asio::io_context::work> aio_work_;
        std::thread io_runner_;
        internal::acceptor acceptor_;

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
