// include/NetworkClient.h
#pragma once
#include <string>

class NetworkClient {
public:
    static bool SendHWIDToServer(const std::string& hwid);
private:
    static bool SendHTTPRequest(const std::string& hwid);
};