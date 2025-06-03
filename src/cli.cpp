#include "../include/cli.h"

Cli::Cli(int argc, char* argv[]) {
    if (argc == 1) {
        std::cerr << "no arguments given... type help\n";
        return;
    }
    this->option = (argc > 1) ? argv[1] : "";
    this->argument = (argc > 2) ? argv[2] : "";
}

void Cli::startCli() {
    if (option == "config") {
        this->setConfigPath(argument);
        return;
    }
    if (option == "genKeys") {
        this->generateEncryptionKeys();
        return;
    }
    if (option == "run") {
        this->run();
        return;
    }
    if (option == "help") {
        std::cout << this->helpCmd << '\n';
        return;
    }

    std::cout << "unknown argument... type help\n";
}

void Cli::setConfigPath(const std::string& configFilePath) {
    const char* homeDir = std::getenv("HOME");
    if (!homeDir) {
        throw std::runtime_error("Could not find HOME directory");
    }

    std::filesystem::path configDir = std::filesystem::path(homeDir) / ".config" / "myvpn";
    std::filesystem::create_directories(configDir); // ensures directory exists

    std::filesystem::path fullPath = configDir / "config_path";

    std::ofstream out(fullPath);
    if (!out.is_open()) {
        throw std::runtime_error("Failed to open config_path file for writing");
    }

    out << configFilePath;
    out.close();
    std::cout << "Configuration path \"" << fullPath.c_str() << "\" successfully set\n";
}

void Cli::generateEncryptionKeys() {
    std::pair<std::string, std::string> keys;
    keys = Util::generateKeyPairBase64();
    if (keys.first.empty() || keys.second.empty()) {
        std::cerr << "Failed to generate keys.\n";
        return;
    }
    std::cout << "Private Key:\n" << keys.first << "\n\n";
    std::cout << "Public Key:\n" << keys.second<< "\n\n";
}

void Cli::startServer(std::map<std::string, std::string>& interfaceMap, std::map<std::string, std::string>& peersMap) {
    std::string address = interfaceMap["address"];
    std::pair<std::string, int> splitAddress = Util::splitBy(address, '/');

    std::string tunName = "vpn_test";
    std::string tunIp = splitAddress.first;
    int tunMask = splitAddress.second;
    int port = std::stoi(interfaceMap["listen_port"]);
    std::string privateKey = interfaceMap["private_key"];
    size_t bufferSize = 1500;

    try {
        VpnServer server(tunName, tunIp, tunMask, port, bufferSize, peersMap, privateKey);
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "Failed to start VPN server: " << e.what() << std::endl;
        return;
    }
}

void Cli::startClient(std::map<std::string, std::string>& interfaceMap, std::map<std::string, std::string>& peerMap) {
    std::string address = interfaceMap["address"];
    std::pair<std::string, int> splitAddress = Util::splitBy(address, '/');
    std::string endpoint = peerMap["endpoint"];
    std::pair<std::string, int> splitEndpoint = Util::splitBy(endpoint, ':');

    std::string tunName = "vpn_test";
    std::string tunIp = splitAddress.first;
    int tunMask = splitAddress.second;
    std::string serverIp = splitEndpoint.first;
    uint16_t serverPort = splitEndpoint.second;
    std::string privateKey = interfaceMap["private_key"];
    std::string serverPublicKey = peerMap["public_key"];

    try {
        VpnClient client(tunName, tunIp, tunMask, serverIp, serverPort, 1500, privateKey, serverPublicKey);
        client.eventLoop();
    } catch (const std::exception& e) {
        std::cerr << "Failed to start VPN client: " << e.what() << std::endl;
        return;
    }
}

void Cli::run() {
    ConfigurationParser configParser;
    std::filesystem::path configPathFile =
        std::filesystem::path(std::getenv("HOME")) / ".config" / "myvpn" / "config_path";

    std::ifstream in(configPathFile);
    if (!in.is_open()) {
        throw std::runtime_error("Failed to open config_path file for reading");
    }

    std::string configPath;
    std::getline(in, configPath);
    in.close();

    if (configParser.parseType(configPath) == "server") {
        std::map<std::string, std::string> interfaceMap;
        std::map<std::string, std::string> peersMap;
        configParser.parseServerConfiguration(configPath, interfaceMap, peersMap);
        this->startServer(interfaceMap, peersMap);
    }
    if (configParser.parseType(configPath) == "client") {
        std::map<std::string, std::string> interfaceMap;
        std::map<std::string, std::string> peerMap;
        configParser.parseClientConfiguration(configPath, interfaceMap, peerMap);
        this->startClient(interfaceMap, peerMap);
    }
}
