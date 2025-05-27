#pragma once
#include <map>
#include <nlohmann/json.hpp>
#include <fstream>
#include <stdexcept>

class ConfigurationParser {
  public:
    ConfigurationParser();
    std::string parseType(const std::string& configPath);
    void parseServerConfiguration(const std::string& configPath, std::map<std::string, std::string>& interfaceMap,
                                  std::map<std::string, std::string>& peersMap);
    void parseClientConfiguration(const std::string& configPath, std::map<std::string, std::string>& interfaceMap,
                                  std::map<std::string, std::string>& peerMap);
};
