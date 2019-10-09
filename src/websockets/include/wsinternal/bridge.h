#include <iostream>

#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif

#include <asio.hpp>
#include <websocketpp/config/asio.hpp>
#include <websocketpp/connection.hpp>

namespace wswrap {
    typedef websocketpp::config::asio::message_type::ptr message_ptr;
    typedef std::shared_ptr<asio::io_service::strand> strand_ptr;
}

namespace internal {
    template<typename WSConnT>
    class bridge : public std::enable_shared_from_this<bridge<WSConnT>> {
            // Private constructor, use create()
            bridge(asio::ip::tcp::socket socket, WSConnT wsconnection)
                : socket_(std::move(socket)), wsconn_(std::move(wsconnection)), strand_ptr_(wsconn_->get_strand()), write_clear(true)
            {
                if (wsconn_ == nullptr) {
                    throw std::invalid_argument("No websocket connection provided.");
                }
            }

        public:
            // Ah, C++ templating can be such a joy
            template<typename ... T>
            static std::shared_ptr<bridge> create(T&& ... all) {
                // Can't use make_shared here because of visibility rules and
                // all that fun jazz...
                auto ptr = std::shared_ptr<bridge>(new bridge(std::forward<T>(all)...));
                ptr->start();
                return ptr;
            }

        private:

            void start() {
                if (wsconn_->get_state() != websocketpp::session::state::open) {
                    // Set an open handler for the websocket connection
                    wsconn_->set_open_handler(
                        strand_ptr_->wrap(std::bind(
                            &bridge::handle_ws_open,
                            this->shared_from_this(),
                            std::placeholders::_1
                        ))
                    );
                } else {
                    // Setup reading from the socket
                    socket_.async_read_some(
                        asio::buffer(socket_data_, max_data_length),
                        strand_ptr_->wrap(std::bind(
                            &bridge::handle_socket_read,
                            this->shared_from_this(),
                            std::placeholders::_1,
                            std::placeholders::_2
                        ))
                    );
                }

                // Set a close handler for the websocket connection
                wsconn_->set_close_handler(
                    strand_ptr_->wrap(std::bind(
                        &bridge::handle_ws_close,
                        this->shared_from_this(),
                        std::placeholders::_1
                    ))
                );

                // Set a message handler for the websocket connection
                wsconn_->set_message_handler(
                    strand_ptr_->wrap(std::bind(
                        &bridge::handle_ws_read,
                        this->shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2
                    ))
                );

                wsconn_->set_interrupt_handler(
                    strand_ptr_->wrap(std::bind(
                        &bridge::handle_ws_interrupt,
                        this->shared_from_this(),
                        std::placeholders::_1
                    ))
                );
            }

            // This handler is called when the websocket handler is open, and
            // we can start sending data into it
            void handle_ws_open(websocketpp::connection_hdl hdl) {
                // Start reading from the socket to forward it on
                socket_.async_read_some(
                    asio::buffer(socket_data_, max_data_length),
                    strand_ptr_->wrap(std::bind(
                        &bridge::handle_socket_read,
                        this->shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2
                    ))
                );
            }

            // This handle will be called when the websocket connection is
            // closed
            void handle_ws_close(websocketpp::connection_hdl hdl) {
                wsconn_->pause_reading();

                // Close out our other socket if the websocket goes away
                close();
            }

            // This handler is called over and over by websocketpp, we do not
            // need to retrigger it
            void handle_ws_read(websocketpp::connection_hdl hdl, wswrap::message_ptr msg) {
                // Append the data to the queue of data to be sent, this copies
                // the data because the lifetime of the payload is determined
                // by websocketpp and we don't control it
                ws_data_.emplace(msg->get_payload());

                // Trigger an async write on the socket as necessary
                maybe_write_to_socket();
            }

            // Unfortunately we can't just keep calling async_write, so we end
            // up having to manually deal with this mess by using a queue and a
            // flag to know when we are done writing.
            void maybe_write_to_socket() {

                if (!ws_data_.empty() && write_clear) {
                    write_clear = false;

                    auto data = ws_data_.front();

                    async_write(socket_,
                        asio::buffer(data),
                        strand_ptr_->wrap(std::bind(&bridge::handle_socket_write,
                            this->shared_from_this(),
                            std::placeholders::_1))
                    );
                }
            }

            // This handler is called once after being triggered, so we need to
            // make sure to trigger it again
            void handle_socket_read(
                const asio::error_code& error,
                const size_t& bytes_transferred
            ) {
                if (!error) {
                    // We received some data, send it to the websocket

                    s_data_.push(std::string(reinterpret_cast<char*>(&socket_data_), bytes_transferred));

                    // We received some data, send it to the websocket
                    wsconn_->interrupt();

                    // Reset trigger so we get called again
                    socket_.async_read_some(
                        asio::buffer(socket_data_, max_data_length),
                        strand_ptr_->wrap(std::bind(
                            &bridge::handle_socket_read,
                            this->shared_from_this(),
                            std::placeholders::_1,
                            std::placeholders::_2
                        ))
                    );

                } else {
                    close();
                }
            }

            // This is triggered when we complete the write that came in from
            // the websocket
            void handle_socket_write(const asio::error_code& error) {
                if (!error) {
                    // Remove the front-most entry
                    ws_data_.pop();

                    // Clear the flag
                    write_clear = true;

                    // Do we have more to send? Do it.
                    maybe_write_to_socket();
                } else {
                    close();
                }
            }

            void handle_ws_interrupt(websocketpp::connection_hdl hdl) {
                std::cerr << "[" << this << "] on_interrupt" << std::endl;

                wsconn_->send(s_data_.front(), websocketpp::frame::opcode::binary);
                s_data_.pop();

                if (!s_data_.empty()) {
                    std::cerr << "Not empty yet, interrupting again" << std::endl;
                    wsconn_->interrupt();
                }

            }
            void close() {
                std::cerr << "Closing the sockets down" << std::endl;
                if (socket_.is_open())
                {
                    socket_.close();
                }

                auto state = wsconn_->get_state();
                if (!(
                     state == websocketpp::session::state::closed ||
                     state == websocketpp::session::state::closing)
                ) {
                    wsconn_->close(websocketpp::close::status::going_away, "socket shutdown");
                }
            }

            asio::ip::tcp::socket socket_;
            WSConnT wsconn_;
            wswrap::strand_ptr strand_ptr_;

            static const int max_data_length = 8192; //8KB
            std::array<unsigned char, max_data_length> socket_data_;
            std::queue<std::string> ws_data_;
            std::queue<std::string> s_data_;
            bool write_clear;
            std::mutex mutex_;
    };
}
