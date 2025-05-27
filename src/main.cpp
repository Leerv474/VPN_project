#include "../include/cli.h"
#include <iostream>


int main(int argc, char* argv[]) {
    Cli cli = Cli(argc, argv);
    cli.startCli();
    return 0;
}
