#pragma once
#include "configuration_parser.h"
#include "vpn_client.h"
#include "vpn_server.h"
#include "util.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
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
};
