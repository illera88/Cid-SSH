#pragma once

#include <memory>
#include <list>
#include <string>

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
