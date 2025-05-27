#pragma once
#include <iostream>

class Util {
  public:
    static std::pair<std::string, int> splitBy(const std::string& string, const char& separator);
};
