#include "../include/tun_device.h"

#define TUN_DEVICE "/dev/net/tun"

TunDevice::TunDevice(const std::string& tunName, const std::string& tunIp, const int tunNetmask, bool setDefaultRoute)
    : tunName(tunName), tunFd(-1), tunNetmask(tunNetmask), setDefaultRoute(setDefaultRoute) {
    struct ifreq ifr; // interface request structure
    memset(&ifr, 0, sizeof(ifr));
    this->tunFd = open(TUN_DEVICE, O_RDWR);

    if (this->tunFd < 0) {
        perror("Opening /dev/net/tun failed");
        throw std::runtime_error("Failed to open TUN device");
    }

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, tunName.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(this->tunFd, TUNSETIFF, &ifr) < 0) {
        perror("ioctl TUNSETIFF failed");
        throw std::runtime_error("Failed to configure TUN device");
    }

    if (!configure(tunIp, tunNetmask)) {
        close(this->tunFd);
        throw std::runtime_error("Tun device configuration failed");
    }

    std::cout << "TUN device " << tunName << " created successfully\n";
}

TunDevice::~TunDevice() {
    if (!this->removeIpTablesRules()) {
        std::cerr << "WARNING: failed to remove iptables rules\n";
    }
    if (this->tunFd >= 0) {
        close(this->tunFd);
        std::cout << "TUN device " << tunName << " closed successfully\n";
    }
}

std::string TunDevice::calculateNetworkAddress(const std::string& ipStr, int prefixLength) {
    in_addr ipAddr;
    if (inet_pton(AF_INET, ipStr.c_str(), &ipAddr) != 1) {
        throw std::runtime_error("Invalid IP");
    }
    uint32_t ip = ntohl(ipAddr.s_addr);

    uint32_t mask = prefixLength == 0 ? 0 : (~0U << (32 - prefixLength));

    uint32_t network = ip & mask;

    in_addr networkAddr;
    networkAddr.s_addr = htonl(network);

    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &networkAddr, buf, sizeof(buf));
    return std::string(buf);
}

std::string TunDevice::getDefaultGateway() {
    std::ifstream routeFile("/proc/net/route");
    std::string line, iface, destination, gateway;
    while (std::getline(routeFile, line)) {
        std::istringstream ss(line);
        ss >> iface >> destination >> gateway;
        if (destination == "00000000") {
            unsigned long gw;
            std::stringstream converter;
            converter << std::hex << gateway;
            converter >> gw;

            struct in_addr addr;
            addr.s_addr = gw;
            return inet_ntoa(addr);
        }
    }
    return "";
}

bool TunDevice::configure(const std::string& tunIp, const int tunNetmask) {
    std::string networkBase = calculateNetworkAddress(tunIp, tunNetmask);
    const std::string ipSetupCmd = "ip addr add " + tunIp + "/" + std::to_string(tunNetmask) + " dev " + this->tunName;
    const std::string disableIpv6Cmd = "sysctl -w net.ipv6.conf." + this->tunName + ".disable_ipv6=1";
    const std::string linkSetCmd = "ip link set dev " + this->tunName + " up";
    const std::string ipForwardingCmd = "sysctl -w net.ipv4.ip_forward=1";
    const std::string forwardingSetupCmd = "iptables -A FORWARD -i vpn_test -j ACCEPT";
    const std::string natSetupCmd = "iptables -t nat -A POSTROUTING -s " + networkBase + "/" +
                                    std::to_string(tunNetmask) + " -o " + this->getDefaultInterface() +
                                    " -j MASQUERADE";
    const std::string ipRoutingCmd =
        "ip route replace " + networkBase + "/" + std::to_string(tunNetmask) + " dev " + this->tunName;
    const std::string delExistingDefaultRouteCmd = "ip route del default";
    const std::string changeDefaultRouteCmd = "ip route add default via " + this->getDefaultGateway() + " dev " + this->getDefaultInterface() + " metric 100";
    const std::string addDefaultRouteCmd = "ip route add default dev " + this->tunName + " metric 10";

    if (system(ipSetupCmd.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << ipSetupCmd << '\n';
        return false;
    }
    if (system(disableIpv6Cmd.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << disableIpv6Cmd << '\n';
        return false;
    }
    if (system(linkSetCmd.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << linkSetCmd << '\n';
        return false;
    }
    if (system(ipForwardingCmd.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << ipForwardingCmd << '\n';
        return false;
    }
    if (system(forwardingSetupCmd.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << forwardingSetupCmd << '\n';
        return false;
    }
    if (system(natSetupCmd.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << natSetupCmd << '\n';
        return false;
    }
    if (system(ipRoutingCmd.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << ipRoutingCmd << '\n';
        return false;
    }
    if (this->setDefaultRoute) {
        if (system(delExistingDefaultRouteCmd.c_str()) != 0) {
            std::cout << "CONFIGURATION FAILED: " << delExistingDefaultRouteCmd << '\n';
            return false;
        }
        if (system(changeDefaultRouteCmd.c_str()) != 0) {
            std::cout << "CONFIGURATION FAILED: " << changeDefaultRouteCmd << '\n';
            return false;
        }
        if (system(addDefaultRouteCmd.c_str()) != 0) {
            std::cout << "CONFIGURATION FAILED: " << addDefaultRouteCmd << '\n';
            return false;
        }
    }

    return true;
}

int TunDevice::getFd() const { return this->tunFd; }

ssize_t TunDevice::readPacket(uint8_t* buffer, size_t bufSize) {
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

ssize_t TunDevice::writePacket(const uint8_t* buffer, size_t bufSize) {
    if (this->tunFd < 0) {
        perror("Unable to write packet, TUN device isn't open");
        return -1;
    }

    ssize_t nwrite = write(this->tunFd, buffer, bufSize);
    if (nwrite < 0) {
        perror("Failed to write TUN device");
        return -1;
    }

    return nwrite;
}

std::string TunDevice::getDefaultInterface() {
    FILE* fp = popen("ip route | grep default | awk '{print $5}'", "r");
    if (!fp)
        return "eth0";

    char buf[64];
    if (fgets(buf, sizeof(buf), fp)) {
        buf[strcspn(buf, "\n")] = '\0';
        pclose(fp);
        return std::string(buf);
    }

    pclose(fp);
    return "eth0";
}

bool TunDevice::removeIpTablesRules() {
    std::string disablePostroutingRules =
        "iptables -t nat -D POSTROUTING -o " + this->getDefaultInterface() + " -j MASQUERADE";
    std::string disableForwardingRules = "iptables -D FORWARD -i " + this->tunName + " -j ACCEPT;";
    if (system(disableForwardingRules.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << disableForwardingRules << '\n';
        return false;
    }
    if (system(disablePostroutingRules.c_str()) != 0) {
        std::cout << "CONFIGURATION FAILED: " << disablePostroutingRules << '\n';
        return false;
    }
    return true;
}
