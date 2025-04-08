#include "../include/vpn_client.h"
#include "../include/vpn_server.h"
#include "../include/vpn_tunnel.h"
#include <iostream>

void startServer() {
  VpnServer server;
  server.start(8088);
}

void startClient() {
  VpnClient client;
  client.connectToServer("127.0.0.1", 8088);
  VpnTunnel tunnel("vpn_test", "10.0.1.2/24");

  tunnel.readPacket(client);
}

int main(int argc, char *argv[]) {
  if (argc == 1) {
    startServer();
  }
  if (argc == 2) {
    startClient();
  }
}
