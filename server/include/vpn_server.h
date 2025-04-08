#pragma once
#include <iostream>
#include <memory>

class VpnServer {
    public:
        VpnServer(const std::string& tunName, int port, size_t bufferSize);
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
        int port;
        size_t bufferSize;
        bool keepAlive = true;

        std::unique_ptr<char[]> buffer;
};
