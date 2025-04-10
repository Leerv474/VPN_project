#pragma once
#include <iostream>
#include <memory>

class VpnServer {
    public:
        VpnServer(const std::string& tunName, const std::string& virtualIp, const std::string& netmask, int port, const std::string& networkDevice, size_t bufferSize);
        ~VpnServer();

        void start();
        void stop();

    private:
        void setupTun();
        void setupServerSocket();
        void acceptClient();
        void eventLoop();

        int tunFd = -1;
        int serverSocketFd = -1;
        int clientFd = -1;
        int epollFd = -1;

        std::string tunName;
        std::string virtualIp;
        std::string netmask;
        int port;
        std::string networkDevice;
        size_t bufferSize;
        bool keepAlive = true;

        std::unique_ptr<char[]> buffer;
};
