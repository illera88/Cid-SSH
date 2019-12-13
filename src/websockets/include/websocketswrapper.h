#ifndef WRAPPER_H_3511F0B7194DD8
#define WRAPPER_H_3511F0B7194DD8

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
    std::list<std::string> get_proxies(std::string c2_uri);
    class impl;
    std::unique_ptr<impl> pimpl_;
};

#endif /* WRAPPER_H_3511F0B7194DD8 */
