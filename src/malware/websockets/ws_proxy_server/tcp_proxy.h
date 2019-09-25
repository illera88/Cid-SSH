#pragma once

#define _WIN32_WINNT 0x0501
#define ASIO_STANDALONE

#include <cstdlib>
#include <cstddef>
#include <iostream>
#include <string>

#include <memory>
#include <functional>
#include <mutex>
#include <random>

#include "asio.hpp"

#include <websocketpp/server.hpp>

namespace tcp_proxy
{
    class bridge : public std::enable_shared_from_this<bridge>
    {
    public:

        typedef asio::ip::tcp::socket socket_type;
        typedef std::shared_ptr<bridge> ptr_type;

        bridge(asio::io_service& ios)
            : downstream_socket_(ios),
            upstream_socket_(ios)
        {}

        socket_type& downstream_socket()
        {
            // Client socket
            return downstream_socket_;
        }

        socket_type& upstream_socket()
        {
            // Remote server socket
            return upstream_socket_;
        }

        void start(const std::string& upstream_host, unsigned short upstream_port)
        {
            // Attempt connection to remote server (upstream side)
            upstream_socket_.async_connect(
                asio::ip::tcp::endpoint(
                    asio::ip::address::from_string(upstream_host),
                    upstream_port),
                std::bind(&bridge::handle_upstream_connect,
                    shared_from_this(),
                    std::placeholders::_1));
        }

        void handle_upstream_connect(const asio::error_code& error)
        {
            if (!error)
            {
                // Setup async read from remote server (upstream)
                upstream_socket_.async_read_some(
                    asio::buffer(upstream_data_, max_data_length),
                    std::bind(&bridge::handle_upstream_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2));

                // Setup async read from client (downstream)
                downstream_socket_.async_read_some(
                    asio::buffer(downstream_data_, max_data_length),
                    std::bind(&bridge::handle_downstream_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2));
            }
            else
                close();
        }

    private:

        /*
           Section A: Remote Server --> Proxy --> Client
           Process data recieved from remote sever then send to client.
        */

        // Read from remote server complete, now send data to client
        void handle_upstream_read(const asio::error_code& error,
            const size_t& bytes_transferred)
        {
            if (!error)
            {
                async_write(downstream_socket_,
                    asio::buffer(upstream_data_, bytes_transferred),
                    std::bind(&bridge::handle_downstream_write,
                        shared_from_this(),
                        std::placeholders::_1));
            }
            else
                close();
        }

        // Write to client complete, Async read from remote server
        void handle_downstream_write(const asio::error_code& error)
        {
            if (!error)
            {
                upstream_socket_.async_read_some(
                    asio::buffer(upstream_data_, max_data_length),
                    std::bind(&bridge::handle_upstream_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2));
            }
            else
                close();
        }
        // *** End Of Section A ***


        /*
           Section B: Client --> Proxy --> Remove Server
           Process data recieved from client then write to remove server.
        */

        // Read from client complete, now send data to remote server
        void handle_downstream_read(const asio::error_code& error,
            const size_t& bytes_transferred)
        {
            if (!error)
            {
                async_write(upstream_socket_,
                    asio::buffer(downstream_data_, bytes_transferred),
                    std::bind(&bridge::handle_upstream_write,
                        shared_from_this(),
                        std::placeholders::_1));
            }
            else
                close();
        }

        // Write to remote server complete, Async read from client
        void handle_upstream_write(const asio::error_code& error)
        {
            if (!error)
            {
                downstream_socket_.async_read_some(
                    asio::buffer(downstream_data_, max_data_length),
                    std::bind(&bridge::handle_downstream_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2));
            }
            else
                close();
        }
        // *** End Of Section B ***

        void close()
        {
            mutex_.lock();
            if (downstream_socket_.is_open())
            {
                downstream_socket_.close();
            }

            if (upstream_socket_.is_open())
            {
                upstream_socket_.close();
            }
            mutex_.unlock();
        }

        socket_type downstream_socket_;
        socket_type upstream_socket_;

        enum { max_data_length = 8192 }; //8KB
        unsigned char downstream_data_[max_data_length];
        unsigned char upstream_data_[max_data_length];

        std::mutex mutex_;

    public:

        class acceptor
        {
        public:

            acceptor(asio::io_service& io_service,
                const std::string& local_host, unsigned short local_port,
                const std::string& upstream_host, unsigned short upstream_port)
                : io_service_(io_service),
                localhost_address(asio::ip::address_v4::from_string(local_host)),
                acceptor_(io_service_, asio::ip::tcp::endpoint(localhost_address, local_port)),
                upstream_port_(upstream_port),
                upstream_host_(upstream_host)
            {}

            bool accept_connections()
            {
                try
                {
                    session_ = std::shared_ptr<bridge>(new bridge(io_service_));

                    acceptor_.async_accept(session_->downstream_socket(),
                        std::bind(&acceptor::handle_accept,
                            this,
                            std::placeholders::_1));
                }
                catch (std::exception& e)
                {
                    std::cerr << "acceptor exception: " << e.what() << std::endl;
                    return false;
                }

                return true;
            }

        private:

            void handle_accept(const asio::error_code& error)
            {
                if (!error)
                {
                    session_->start(upstream_host_, upstream_port_);

                    if (!accept_connections())
                    {
                        std::cerr << "Failure during call to accept." << std::endl;
                    }
                }
                else
                {
                    std::cerr << "Error: " << error.message() << std::endl;
                }
            }

            asio::io_service& io_service_;
            asio::ip::address_v4 localhost_address;
            asio::ip::tcp::acceptor acceptor_;
            ptr_type session_;
            unsigned short upstream_port_;
            std::string upstream_host_;
        };

    };
}

int proxy_listen(const std::string forward_host, const unsigned short forward_port, unsigned short* listening_proxy_port)
{
    const std::string local_host = "127.0.0.1";
    asio::io_service ios;

    int i = 0;
    while (i < 20) { // let's try 20 times to find an available port before returning error
        i++;
        std::random_device seeder;
        std::mt19937 engine(seeder());
        std::uniform_int_distribution<unsigned short> dist(1200, 65535);
        unsigned short local_port = dist(engine);

        try
        {
            tcp_proxy::bridge::acceptor acceptor(ios,
                local_host, local_port,
                forward_host, forward_port);

            acceptor.accept_connections();

            *listening_proxy_port = local_port;

            ios.run();
        }
        catch (std::exception& e)
        {
            std::cerr << "Error: " << e.what() << " Port " << local_port << "seems to be taken. Trying a different one" << std::endl;
            continue;
        }
    }
    return 0;
}


/* Returns the port in which the proxy server is listening*/
int start_proxy_server(const std::string forward_host, const unsigned short forward_port) {
    
    unsigned short TCP_proxy_listening_port = 0;
    std::thread TCP_proxy_thread(proxy_listen, forward_host, forward_port, &TCP_proxy_listening_port); // webserver must be in port 443 same as SSH server is in 22

    for (auto i = 0; i < 10; i++) { // Wait up to 3 seconds to get a valid port
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        if (TCP_proxy_listening_port != 0) {
            //debug("Starting TCP proxy at 127.0.0.1:%d\n", TCP_proxy_listening_port);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    if (TCP_proxy_listening_port == 0) {
        //debug("Some error starting the TCP proxy. Exiting...\n");
        return 1;
    }

    return TCP_proxy_listening_port;

    
}

int stop_proxy_server(asio::io_service* ios) {
    ios->stop();

    return 0;
}