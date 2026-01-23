//
// Created by sexey on 20.01.2026.
//
module;
#include <algorithm>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

export module entunnel.http_parser;

namespace entunnel::http
{
    export using hears_map_t = std::unordered_map<std::string, std::vector<std::string>>;

    export struct http_request_s
    {
        //std::string method;
        std::string uri; // its status code, but for clarity im named it uri
        hears_map_t headers;
        //std::string body;
    };

    std::string Trim(const std::string_view& str)
    {
        const auto strBegin = str.find_first_not_of(" \t");
        if (strBegin == std::string::npos) {
            return "";
        }

        const auto strEnd = str.find_last_not_of(" \t");
        const auto range = strEnd - strBegin + 1;

        return std::string(str.substr(strBegin, range));
    }

    std::string ToLower(std::string s)
    {
        std::ranges::transform(s, s.begin(), [](unsigned char c){ return std::tolower(c); });
        return s;
    }

    export http_request_s Parse(const std::string_view& raw)
    {
        http_request_s request;

        auto currentPos = raw.begin();
        const auto end = raw.end();

        auto getLine = [&](std::string_view& lineView) -> bool {
            if (currentPos == end) {
                return false;
            }

            // Handle CRLF or just LF
            const auto lineEnd = std::find(currentPos, end, '\n');
            auto lineLen = std::distance(currentPos, lineEnd);
            if (lineLen > 0 && *(lineEnd - 1) == '\r') {
                lineLen--;
            }

            lineView = {&*currentPos, static_cast<size_t>(lineLen)};

            currentPos = lineEnd;
            if (currentPos != end) {
                ++currentPos;
            }

            return true;
        };

        std::string_view line;

        if (getLine(line) && !line.empty()) {
            if (const auto firstSpace = line.find(' '); firstSpace != std::string_view::npos) {
                //request.method = std::string(line.substr(0, firstSpace));

                if (const auto secondSpace = line.find(' ', firstSpace + 1);
                    secondSpace != std::string_view::npos) {
                    request.uri = std::string(line.substr(firstSpace + 1, secondSpace - firstSpace - 1));
                } else {
                    request.uri = Trim(line.substr(firstSpace + 1));
                }
            }
        }

        while (getLine(line)) {
            if (line.empty()) {
                break;
            }

            if (const auto colonPos = line.find(':'); colonPos != std::string_view::npos) {
                auto key = ToLower(Trim(line.substr(0, colonPos)));
                request.headers[std::move(key)].push_back(Trim(line.substr(colonPos + 1)));
                (void)key;
            }
        }

        //if (current_pos != end) {
        //    request.body = std::string(current_pos, end);
        //}

        return request;
    }
}
