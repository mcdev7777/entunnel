//
// Created by sexey on 22.01.2026.
//
module;
#include <windows.h>
#include <format>
#include <string_view>

export module entunnel;
import entunnel.tcp_tunnel;
import entunnel.sspi_auth;
import entunnel.proxy;
import entunnel.encoding;
import entunnel.http_parser;

namespace entunnel
{
    constexpr auto REQUEST_STUB = "CONNECT {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n";

    constexpr auto CRLF_POSTFIX = "\r\n\r\n";

    export class C_Entunnel
    {
    public:
        ~C_Entunnel() = default;
        C_Entunnel() = default;

        bool initialize(const std::wstring_view& address)
        {
            const auto proxy = proxy::GetSystemProxyForUrl(address);
            if (!proxy.has_value()) {
                return false;
            }

            if (!this->tunnel_.initialize()) {
                return false;
            }

            if (!this->tunnel_.connect(proxy->addr, proxy->port)) {
                return false;
            }

            auto convertedAddress = encoding::string::ToUtf8(address);
            if (convertedAddress.empty()) {
                return false;
            }

            this->requestStub_ = std::format(REQUEST_STUB, convertedAddress, convertedAddress);
            return true;
        }

        SOCKET createTunnel()
        {
            if (const auto err = requestAuthSchema(); err == SOCKET_ERROR) {
                return err;
            } else if (err == ERROR_SUCCESS) {
                return this->tunnel_.release();
            }

            if (!handshakeRoutine()) {
                return SOCKET_ERROR;
            }

            return this->tunnel_.release();
        }

    private:
        bool handle407(const http::hears_map_t& headers, const win::sspi::C_SSPI::auth_result_s& sspiResult)
        {
            if (sspiResult.isCompleted && !sspiResult.needContinue) { // authentication failed
                return false;
            }

            const auto authTokenIT = headers.find("proxy-authenticate");
            if (authTokenIT == headers.end() || authTokenIT->second.empty()) {
                return false;
            }

            const auto prefix = std::format("{} ", this->sspi_.scheme());
            const auto& headerValue = authTokenIT->second[0];

            const auto tokenStart = headerValue.find(prefix);
            if (tokenStart == std::string::npos) {
                return false;
            }

            this->serverChallenge_ = headerValue.substr(tokenStart + prefix.length());
            return true;
        }

        bool handshakeRoutine()
        {
            for (auto i = 0; i < 3; ++i) {
                const auto sspiResult = this->sspi_.processChallenge(this->serverChallenge_);
                if (!sspiResult.has_value()) {
                    return false;
                }

                auto request = this->requestStub_;
                if (!sspiResult->token.empty()) {
                    request += std::format("Proxy-Authorization: {} {}\r\n", this->sspi_.scheme(), sspiResult->token);
                }

                request += "\r\n";
                if (!this->tunnel_.send({ reinterpret_cast<uint8_t*>(request.data()), request.size() })) {
                    return false;
                }

                const auto response = readProxyResponse();
                if (response.empty()) {
                    return false;
                }

                const auto [uri, headers] = http::Parse({ reinterpret_cast<const char*>(response.data()), response.size() });
                if (uri == "200") {
                    return true;
                } else if (uri == "407" && !handle407(headers, sspiResult.value())) {
                    return false;
                }
            }

            return false;
        }

        std::vector<uint8_t> readProxyResponse()
        {
            std::vector<uint8_t> response;

            size_t headerEndPos = std::string::npos;
            while (headerEndPos == std::string::npos) {
                auto chunk = this->tunnel_.receive(4096);
                if (chunk.empty()) {
                    return {};
                }

                response.insert(response.end(), chunk.begin(), chunk.end());

                std::string_view view(reinterpret_cast<const char*>(response.data()), response.size());
                headerEndPos = view.find(CRLF_POSTFIX);
                if (response.size() > 16384 && headerEndPos == std::string::npos) {
                    return {};
                }
            }

            const std::string_view headersPart(reinterpret_cast<const char*>(response.data()), headerEndPos);
            auto [uri, headers] = entunnel::http::Parse(headersPart);

            const auto contentLengthIT = headers.find("content-length");
            if (contentLengthIT == headers.end() || contentLengthIT->second.empty()) {
                return response;
            }

            const auto totalBodyLen = std::atoi(contentLengthIT->second[0].c_str()); // NOLINT(*-err34-c)
            const size_t headersFullSize = headerEndPos + strlen(CRLF_POSTFIX);
            const auto bodyBytesAlreadyRead = response.size() - headersFullSize;

            if (const auto bytesRemaining = totalBodyLen - bodyBytesAlreadyRead; bytesRemaining > 0) {
                this->tunnel_.receive(bytesRemaining); // We dont need a body
            }

            return response;
        }

        int32_t requestAuthSchema()
        {
            auto request = this->requestStub_ + "\r\n";
            if (!this->tunnel_.send({ reinterpret_cast<uint8_t*>(request.data()), request.size() })) {
                return SOCKET_ERROR;
            }

            const auto response = readProxyResponse();
            if (response.empty()) {
                return SOCKET_ERROR;
            }

            const auto [uri, headers] = http::Parse(std::string{ reinterpret_cast<const char*>(response.data()), response.size() });
            if (uri == "200") {
                return ERROR_SUCCESS;
            }

            const auto authSchemeIt = headers.find("proxy-authenticate");
            if (authSchemeIt == headers.end() || authSchemeIt->second.empty()) {
                return SOCKET_ERROR;
            }

            const auto convertedAddress = encoding::string::ToUtf8(this->tunnel_.address());
            if (!this->sspi_.initialize(authSchemeIt->second[0], convertedAddress)) {
                return SOCKET_ERROR;
            }

            return ERROR_CONTINUE;
        }

        inet::tunnel::C_TcpTunnel tunnel_;
        win::sspi::C_SSPI sspi_;
        std::string requestStub_;
        std::string serverChallenge_;
    };
}
