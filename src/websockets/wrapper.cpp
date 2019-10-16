#include <iostream>
#include <stdexcept>
#include <thread>

#include <websocketswrapper.h>
#include <wsinternal/bridge.h>
#include <wsinternal/acceptor.h>

namespace net = boost::asio;
using wsinternal::wsstream;



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
                net::ip::address_v4::loopback(),
                0,
                [&] (asio::ip::tcp::socket socket) {
                    auto bridge = internal::bridge<wswrap::client::connection_ptr>::create(std::move(socket), std::move(websocket_connection));
                }
            )
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
        net::io_context io_context_;
        net::ssl::context ssl_context_;
        std::shared_ptr<net::io_context::work> aio_work_;
        std::thread io_runner_;
        wsinternal::acceptor acceptor_;

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
