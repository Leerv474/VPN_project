#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdexcept>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../include/vpn_tunnel.h"

#define TUN_DEVICE "/dev/net/tun"
#define BUFFER_SIZE 2048

TunDevice::TunDevice(const std::string& devName, const std::string& deviceIp, const std::string& netmask,
                     const std::string& networkDevice)
    : deviceName(devName), tunFd(-1) {
    struct ifreq ifr; // interface request structure
    memset(&ifr, 0, sizeof(ifr));
    this->tunFd = open(TUN_DEVICE, O_RDWR);

    if (this->tunFd < 0) {
        perror("Opening /dev/net/tun failed");
        throw std::runtime_error("Failed to open TUN device");
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, deviceName.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(this->tunFd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF failed");
        throw std::runtime_error("Failed to configure TUN device");
    }

    if (!configure(deviceIp, netmask, networkDevice)) {
        close(this->tunFd);
        throw std::runtime_error("Tun device configuration failed");
    }

    std::cout << "TUN device " << deviceName << " created successfully\n";
}

TunDevice::~TunDevice() {
    if (this->tunFd >= 0) {
        close(this->tunFd);
        std::cout << "TUN device " << deviceName << " closed successfully\n";
    }
}

bool TunDevice::configure(const std::string& deviceIp, const std::string& netmask, const std::string& networkDevice) {
    const std::string ipSetupCmd = "ip addr add " + deviceIp + "/" + netmask + " dev " + this->deviceName;
    const std::string linkSetCmd = "ip link set dev " + this->deviceName + " up";
    const std::string ipForwardingCmd = "sysctl -w net.ipv4.ip_forward=1";
    const std::string natSetupCmd =
        "iptables -t nat -A POSTROUTING -s " + deviceIp + "/" + netmask + "-o " + networkDevice + " -j MASQUERADE";
    const std::string ipRoutingCmd = "ip route add " + deviceIp + "/" + netmask + " dev " + this->deviceName;

    if (system(ipSetupCmd.c_str()) != 0)
        return false;
    if (system(linkSetCmd.c_str()) != 0)
        return false;
    if (system(ipForwardingCmd.c_str()) != 0)
        return false;
    if (system(natSetupCmd.c_str()) != 0)
        return false;
    if (system(ipRoutingCmd.c_str()) != 0)
        return false;

    return true;
}

int TunDevice::getFd() const { return this->tunFd; }

ssize_t TunDevice::readPacket(char* buffer, size_t bufSize) {
    if (this->tunFd < 0) {
        perror("Unable to read packet, TUN device isn't open");
        return -1;
    }

    ssize_t nread = read(this->tunFd, buffer, bufSize);
    if (nread < 0) {
        perror("Failed to read TUN device");
        return -1;
    }

    return nread;
}

ssize_t TunDevice::writePacket(const char* buffer, size_t bufSize) {
    if (this->tunFd < 0) {
        perror("Unable to write packet, TUN device isn't open");
        return -1;
    }

    ssize_t nwrite = write(this->tunFd, buffer, bufSize);
    if (nwrite < 0) {
        perror("Failed to read TUN device");
        return -1;
    }

    return nwrite;
}
