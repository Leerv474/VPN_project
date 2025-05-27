#include "../include/configuration_parser.h"

using json = nlohmann::json;
ConfigurationParser::ConfigurationParser() {}

std::string ConfigurationParser::parseType(const std::string& configPath) {
    std::ifstream inputFile(configPath);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Failed to open config file: " + configPath);
    }

    json config;
    try {
        inputFile >> config;
    } catch (const json::parse_error& e) {
        throw std::runtime_error(std::string("JSON parse error: ") + e.what());
    }

    std::string type;
    try {
        type = config.at("type").get<std::string>();
        if (type != "server" && type != "client") {
            throw std::runtime_error("Invalid configuration type");
        }
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("Missing or invalid 'type': ") + e.what());
    }
    return type;
}

void ConfigurationParser::parseServerConfiguration(const std::string& configPath,
                                                   std::map<std::string, std::string>& interfaceMap,
                                                   std::map<std::string, std::string>& peersMap) {
    std::ifstream inputFile(configPath);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Failed to open config file: " + configPath);
    }

    json config;
    try {
        inputFile >> config;
    } catch (const json::parse_error& e) {
        throw std::runtime_error(std::string("JSON parse error: ") + e.what());
    }

    std::string type;
    try {
        type = config.at("type").get<std::string>();
        if (type != "server" && type != "client") {
            throw std::runtime_error("Invalid configuration type");
        }
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("Missing or invalid 'type': ") + e.what());
    }

    interfaceMap.clear();
    peersMap.clear();

    try {
        const json& iface = config.at("interface");
        if (!iface.contains("address") || !iface.contains("listen_port") || !iface.contains("private_key")) {
            throw std::runtime_error(
                "Missing required keys in 'interface' section (expected: address, listen_port, private_key)");
        }

        interfaceMap["address"] = iface.at("address").get<std::string>();
        interfaceMap["listen_port"] = std::to_string(iface.at("listen_port").get<int>());
        interfaceMap["private_key"] = iface.at("private_key").get<std::string>();
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("Missing or invalid 'interface': ") + e.what());
    }

    try {
        const json& peersArray = config.at("peers");
        if (!peersArray.is_array()) {
            throw std::runtime_error("'peers' should be an array");
        }

        for (const auto& peer : peersArray) {
            if (!peer.contains("allowed_ip") || !peer.contains("public_key")) {
                throw std::runtime_error("Missing required keys in 'peer' section (expected: alllowed_ip, public_key)");
            }
            std::string allowed_ip = peer.at("allowed_ip").get<std::string>();
            std::string public_key = peer.at("public_key").get<std::string>();
            peersMap[allowed_ip] = public_key;
        }
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("Invalid 'peers' section: ") + e.what());
    }
}

void ConfigurationParser::parseClientConfiguration(const std::string& configPath,
                                                   std::map<std::string, std::string>& interfaceMap,
                                                   std::map<std::string, std::string>& peerMap) {
    std::ifstream inputFile(configPath);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Failed to open config file: " + configPath);
    }

    json config;
    try {
        inputFile >> config;
    } catch (const json::parse_error& e) {
        throw std::runtime_error(std::string("JSON parse error: ") + e.what());
    }

    std::string type;
    try {
        type = config.at("type").get<std::string>();
        if (type != "server" && type != "client") {
            throw std::runtime_error("Invalid configuration type");
        }
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("Missing or invalid 'type': ") + e.what());
    }

    interfaceMap.clear();
    peerMap.clear();

    try {
        const json& iface = config.at("interface");
        if (!iface.contains("address") || !iface.contains("private_key")) {
            throw std::runtime_error("Missing required keys in 'interface' section (expected: address, private_key)");
        }

        interfaceMap["address"] = iface.at("address").get<std::string>();
        interfaceMap["private_key"] = iface.at("private_key").get<std::string>();
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("Missing or invalid 'interface': ") + e.what());
    }

    try {
        const json& iface = config.at("peer");
        if (!iface.contains("endpoint") || !iface.contains("allowed_ips") || !iface.contains("public_key")) {
            throw std::runtime_error(
                "Missing required keys in 'interface' section (expected: endpoint, allowed_ips, public_key)");
        }

        peerMap["endpoint"] = iface.at("endpoint").get<std::string>();
        peerMap["allowed_ips"] = iface.at("allowed_ips").get<std::string>();
        peerMap["public_key"] = iface.at("public_key").get<std::string>();
    } catch (const json::exception& e) {
        throw std::runtime_error(std::string("Invalid 'peer' section: ") + e.what());
    }
}
