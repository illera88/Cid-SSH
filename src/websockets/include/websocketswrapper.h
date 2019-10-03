#ifndef WRAPPER_H_3511F0B7194DD8
#define WRAPPER_H_3511F0B7194DD8

#include <string>
#include <memory>

class WebsocketsWrapper {
    public:
        WebsocketsWrapper(std::string);
        std::string& local_ip();
        unsigned int local_port();
        ~WebsocketsWrapper();

    private:
        class impl;
        std::unique_ptr<impl> pimpl_;
};

#endif /* WRAPPER_H_3511F0B7194DD8 */
