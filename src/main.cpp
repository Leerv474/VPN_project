#include "../include/cli.h"

int main(int argc, char* argv[]) {
    Cli cli = Cli(argc, argv);
    cli.startCli();
    return 0;
}
