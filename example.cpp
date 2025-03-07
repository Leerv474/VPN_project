#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <cstring>


#define TUN_DEVICE "/dev/net/tun"
#define BUFFER_SIZE 2048

int createTunDevice(std::string tunName) {
    struct ifreq ifr;
    int fileDescriptor = open(TUN_DEVICE, O_RDWR);
    if (fileDescriptor < 0) {
        perror("opening /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, tunName.c_str(), IFNAMSIZ);


    if(ioctl(fileDescriptor, TUNSETIFF, &ifr) < 0) {
        perror("creating tun device");
        close(fileDescriptor);
        return -1;
    }

    std::cout << "TUN device " << ifr.ifr_name << " created successfully.\n";
    return fileDescriptor;
}

int main() {
    std::string tunName = "tun0";
    int tunFileDescriptor = createTunDevice(tunName);
    if (tunFileDescriptor < 0) return 1;

    char buffer[BUFFER_SIZE];

    while(true) {
        int nread = read(tunFileDescriptor, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("reading from tun device");
            break;
        }

        std::cout << "received " << nread << " bytes from " << tunName << '\n';

        int nwrite = write(tunFileDescriptor, buffer, nread);
        if (nwrite< 0) {
            perror("write to tun device");
            break;
        }
    }

    close(tunFileDescriptor);
    return 0;
}
