#include <iostream>
#include <thread>

#include <websocketswrapper.h>

#include <wsinternal/acceptor.h>
#include <wsinternal/bridge.h>
#include <wsinternal/wsconn.h>

namespace net = boost::asio;
using wsinternal::wsstream;

namespace wsinternal {
class shared_storage {
public:
    shared_storage(net::ip::tcp::socket&& socket)
        : socket_(std::move(socket))
    {
    }

    net::ip::tcp::socket get_socket()
    {
        return std::move(socket_);
    }

private:
    net::ip::tcp::socket socket_;
};
} // namespace wsinternal

WebsocketsWrapper::WebsocketsWrapper(std::string c2_uri)
    : pimpl_(std::make_unique<WebsocketsWrapper::impl>(c2_uri))
{
}

WebsocketsWrapper::~WebsocketsWrapper()
{
}

class WebsocketsWrapper::impl {
public:
    impl(std::string& c2_uri)
        : uri_(c2_uri)
        , ssl_context_(net::ssl::context::tlsv12_client)
        , aio_work_(std::make_shared<net::io_context::work>(io_context_))
        , io_runner_(
              std::thread(
                  [&] {
                      // Start up the asio context in a thread, forever
                      io_context_.run();
                  }))
        , acceptor_(
              io_context_,
              net::ip::address_v4::loopback(),
              0,
              // Capture everything by reference, so we can re-use things like io_context_/ssl_context_/uri_
              [&](net::ip::tcp::socket&& socket) {
                  // Create a shared pointer that holds the socket by moving it into the shared storage
                  auto storage = std::make_shared<wsinternal::shared_storage>(std::move(socket));

                  // Create a new shared wsconn which will go do the whole song and dance to get connected to a websocket
                  wsinternal::wsconn::create(
                      io_context_,
                      ssl_context_,
                      uri_,
                      // Lambda copies storage (thereby increasing the shared_ptr) and captures it
                      [storage](wsstream&& wsocket) {
                          // Using our storage shared pointer we get the socket, and move it into the bridge
                          // alongside moving the websocket into the bridge
                          wsinternal::bridge::create(std::move(storage->get_socket()), std::move(wsocket));
                      });
              })
    {
        acceptor_.accept_connections();

        // Get the local information and store it upon creation
        auto local_info = acceptor_.local_endpoint();
        local_ip_ = local_info.address().to_string();
        local_port_ = local_info.port();
    }

    ~impl()
    {
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

std::string& WebsocketsWrapper::local_ip()
{
    return pimpl_->local_ip_;
}

unsigned int WebsocketsWrapper::local_port()
{
    return pimpl_->local_port_;
}
