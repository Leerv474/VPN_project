#include "../include/cli.h"
#include <iostream>

#include "../include/authenticator.h"
#include "../include/configuration_parser.h"
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string>
#include <vector>

// int main() {
//     ConfigurationParser parser;
//     try {
//         std::map<std::string, std::string> interfaceMap;
//         std::map<std::string, std::string> peerMap;
//         parser.parseClientConfiguration("../client-config-1.json", interfaceMap,
//                                          peerMap);
//         std::string privateKey = interfaceMap["private_key"];
//         parser.parseServerConfiguration("../server-config.json", interfaceMap, peerMap);
//         std::string publicKey = peerMap["10.0.1.2"];
//
//         Authenticator auth(privateKey);
//
//         std::vector<uint8_t> challenge = auth.generateChallenge(32);
//         std::vector<uint8_t> signature = auth.signChallenge(challenge);
//
//         bool ok = auth.verifyChallenge(publicKey, challenge, signature);
//
//         std::cout << "Signature verification: " << (ok ? "✅ SUCCESS" : "❌ FAILURE") << std::endl;
//     } catch (const std::exception& e) {
//         std::cerr << "Exception: " << e.what() << '\n';
//         return 1;
//     }
//
//     return 0;
// }
int main(int argc, char* argv[]) {
    Cli cli = Cli(argc, argv);
    cli.startCli();
    return 0;
}
