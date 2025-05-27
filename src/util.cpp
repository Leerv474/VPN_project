#include "../include/util.h"

std::pair<std::string, int> Util::splitBy(const std::string& string, const char& separator) {
        size_t pos = string.find(separator);
        // std::cout << "Trying to separate " << string << " " << separator << "\n\n";
        if (pos == std::string::npos) {
            throw std::invalid_argument("Separator not found");
        }

        std::string ip = string.substr(0, pos);
        int remainder = std::stoi(string.substr(pos + 1));

        return {ip, remainder};
    }
