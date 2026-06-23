#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <regex>

namespace snapescape {

struct ProtocolAnalysis {
    std::string protocol;
    std::string version;
    std::map<std::string, std::string> headers;
    std::vector<std::string> anomalies;
};

class ProtocolAnalyzer {
public:
    static ProtocolAnalysis analyze_http(const std::string& raw) {
        ProtocolAnalysis result;
        std::istringstream stream(raw);
        std::string line;
        if (std::getline(stream, line)) {
            std::regex re(R"((\w+)\s+(\S+)\s+(\S+))");
            std::smatch m;
            if (std::regex_match(line, m, re)) {
                result.protocol = "HTTP";
                result.version = m[3];
            }
        }
        while (std::getline(stream, line) && line != "\r" && !line.empty()) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string val = line.substr(pos + 2);
                result.headers[key] = val;
                if (key == "Transfer-Encoding" && result.headers.count("Content-Length"))
                    result.anomalies.push_back("TE/CL conflict — potential smuggling");
            }
        }
        return result;
    }

    static std::vector<uint16_t> scan_ports(const std::string& host,
        const std::vector<uint16_t>& ports) {
        std::vector<uint16_t> open;
        for (auto port : ports) {
            // Delegates to C packet engine at link time
            extern int snapescape_tcp_probe(const char*, uint16_t, int);
            if (snapescape_tcp_probe(host.c_str(), port, 1000) == 0)
                open.push_back(port);
        }
        return open;
    }
};

}  // namespace snapescape
