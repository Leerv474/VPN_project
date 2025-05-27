#pragma once
#include <iostream>
#include <map>
#include "../include/util.h"
#include "../include/configuration_parser.h"
#include "../include/vpn_client.h"
#include "../include/vpn_server.h"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>


class Cli {
  public:
    Cli(int argc, char* argv[]);
    void startCli();

  private:
    void run();
    void startClient(std::map<std::string, std::string>& interfaceMap, std::map<std::string, std::string>& peersMap);
    void startServer(std::map<std::string, std::string>& interfaceMap, std::map<std::string, std::string>& peerMap);
    void setConfigPath(const std::string& configFilePath);
    void generateEncryptionKeys();

    std::string option;
    std::string argument;
    const std::string helpCmd = "--- help ---\n> config <config_path> - set config path\n> genKeys - generate "
                                "encryption keys\n> run - run vpn with current configuration";

    Util util;
};
