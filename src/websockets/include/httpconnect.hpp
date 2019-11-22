#include <iostream>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/async_base.hpp>
#include <boost/beast/core/detail/is_invocable.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/error.hpp>
#include <boost/beast/http/message.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/verb.hpp>
#include <boost/beast/http/write.hpp>

// This is likely a bad idea, since it's not public API
#include <boost/beast/core/detail/base64.hpp>

namespace httpconnect {
namespace beast = ::boost::beast;
namespace net = ::boost::asio;

template <
    class Stream,
    class Handler,
    class Buffer,
    class base_type = boost::beast::async_base<
        Handler, typename Stream::executor_type>>
class httpconnect_op : public base_type {
public:
    httpconnect_op(httpconnect_op&&) = default;
    httpconnect_op(httpconnect_op const&) = default;

    httpconnect_op(
        Stream& stream,
        Handler& handler,
        const std::string& hostname,
        const std::string& port,
        const std::string& username,
        const std::string& password)
        : base_type(std::move(handler), stream.get_executor())
        , stream_(stream)
        , hostname_(hostname)
        , port_(port)
        , username_(username)
        , password_(password)
    {
        (*this)({}, 0); // start the operation
    }

    void
    operator()(
        std::error_code ec,
        std::size_t bytes_transferred)
    {
        boost::ignore_unused(bytes_transferred);

        auto& request = *request_;
        auto& response = *response_;

        switch (ec ? 10 : step_) {
        case 0: {
            step_ = 1;

            auto target = hostname_ + ":" + port_;

            req_.version(11);
            req_.method(beast::http::verb::connect);
            req_.target(target);
            req_.set(beast::http::field::host, target);

            if (username_ != "" and password_ != "") {
                auto user_pass = username_ + ":" + password_;
                auto b64encoded = std::vector<char> {};
                b64encoded.resize(beast::detail::base64::encoded_size(user_pass.length()));
                beast::detail::base64::encode(b64encoded.data(), user_pass.c_str(), user_pass.length());
                auto basic_auth = std::string("Basic ") + std::string(b64encoded.data(), b64encoded.size());
                req_.set(beast::http::field::proxy_authorization, basic_auth);
            }

            return beast::http::async_write(
                stream_,
                req_,
                std::move(*this));
        }
        case 1: {
            // Now we get the response, we unfortunately have to read 1 byte at
            // a time so we don't accidentally read too much data from the
            // wire. We will return to this step multiple times, so we need to.
            // Check that the last four bytes of the response are \r\n\r\n,
            // then we need to hand it off to parsing

            bool end_of_http = false;

            if (response.size() >= 4) {
                auto response_data = static_cast<const char*>(response.data().data());
                end_of_http = std::string("\r\n\r\n").compare(response_data + (response.size() - 4));

                if (end_of_http) {
                    step_ = 2;
                    return (*this)(ec, 0);
                }
            }

            return net::async_read(
                stream_,
                response,
                net::transfer_exactly(1),
                std::move(*this));
        }
        case 2: {
            step_ = 3;

            // We now need to parse the HTTP response that should be sitting in
            // the response_

            auto& response = *response_;
            beast::http::response_parser<beast::http::string_body> http_response{};
            boost::beast::error_code put_ec;
            http_response.put(response.data(), put_ec);

            if (put_ec) {
                this->complete_now(put_ec);
            }

            if (http_response.get().result() == beast::http::status::ok) {
                this->complete_now(ec);
            } else {
                this->complete_now(boost::beast::http::make_error_code(beast::http::error::bad_status));
            }
            break;
        }
        }
    }

private:
    Stream& stream_;

    using BufferPtr = std::unique_ptr<Buffer>;
    BufferPtr request_ { new Buffer() };
    BufferPtr response_ { new Buffer() };

    beast::http::request<beast::http::empty_body> req_;

    std::string hostname_;
    std::string port_;
    std::string username_;
    std::string password_;
    bool use_hostname_;
    int step_ = 0;
};

/** Perform the HTTP CONNECT handshake.
*/
template <
    typename AsyncStream,
    typename Handler>
BOOST_BEAST_ASYNC_RESULT1(Handler)
async_handshake_httpconnect(
    AsyncStream& stream,
    const std::string& hostname,
    const std::string& port,
    std::string const& username,
    std::string const& password,
    Handler&& handler)
{
    net::async_completion<Handler, void(std::error_code)> init { handler };
    using HandlerType = typename std::decay<decltype(init.completion_handler)>::type;

    static_assert(boost::beast::detail::is_invocable<HandlerType,
                      void(std::error_code)>::value,
        "Handler type requirements not met");

    using Buffer = net::basic_streambuf<typename std::allocator_traits<
        net::associated_allocator_t<HandlerType>>::template rebind_alloc<char>>;

    httpconnect_op<AsyncStream, HandlerType, Buffer>(stream, init.completion_handler,
        hostname, port, username, password);

    return init.result.get();
}

} // httpconnect
