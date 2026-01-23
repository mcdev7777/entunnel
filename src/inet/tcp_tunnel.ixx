//
// Created by sexey on 19.01.2026.
//
module;
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

export module entunnel.tcp_tunnel;
import entunnel.scoped_socket;

namespace entunnel::inet::tunnel
{
    constexpr ADDRINFOW RESOLVER_OPTS = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP
    };

    struct addrinfo_destructor_s
    {
        void operator()(ADDRINFOW* ptr) const noexcept
        {
            if (ptr) {
                FreeAddrInfoW(ptr);
            }
        }
    };

    struct socket_destructor_s
    {
        void operator()(SOCKET ptr) const noexcept
        {
            if (ptr != INVALID_SOCKET) {
                closesocket(ptr);
            }
        }
    };

    export class C_TcpTunnel
    {
    public:
        ~C_TcpTunnel() { WSACleanup(); }
        C_TcpTunnel() : isInitialized_(false), isConnected_(false) {}

        C_TcpTunnel(const C_TcpTunnel&) = delete;
        C_TcpTunnel& operator=(const C_TcpTunnel&) = delete;
        C_TcpTunnel(C_TcpTunnel&& other) noexcept;
        C_TcpTunnel& operator=(C_TcpTunnel&& other) noexcept;

        [[nodiscard]] bool isInitialized() const noexcept { return this->isInitialized_; }

        [[nodiscard]] bool isConnected() const noexcept { return this->isConnected_; }

        [[nodiscard]] const std::wstring& address() const noexcept { return this->address_; }

        [[nodiscard]] SOCKET socket() const noexcept { return this->socket_.get(); }

        [[nodiscard]] SOCKET release() noexcept { return this->socket_.release(); }

        [[nodiscard]] bool initialize() noexcept
        {
            if (isInitialized()) {
                return true;
            }

            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
                return false;
            }

            this->isInitialized_ = true;
            return true;
        }

        void disconnect() noexcept
        {
            if (!this->isConnected_) {
                return;
            }

            shutdown(this->socket_.get(), SD_BOTH);
            this->socket_.close();
            this->isConnected_ = false;
        }

        bool connect(const std::wstring_view& addr, const uint16_t port)
        {
            if (!isInitialized() || isConnected()) {
                return false;
            }

            std::unique_ptr<ADDRINFOW, addrinfo_destructor_s> addrInfo;
            if (GetAddrInfoW(addr.data(), std::to_wstring(port).c_str(),
                &RESOLVER_OPTS, reinterpret_cast<PADDRINFOW*>(&addrInfo)) != NO_ERROR) {
                return false;
            }

            for (auto ptr = addrInfo.get(); ptr != nullptr; ptr = ptr->ai_next) {
                this->socket_.reset(::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol));
                if (!this->socket_.isValid()) {
                    continue;
                }

                if (::connect(this->socket_.get(), ptr->ai_addr, static_cast<int32_t>(ptr->ai_addrlen)) != NO_ERROR) {
                    continue;
                }

                this->isConnected_ = true;
                break;
            }

            this->address_ = addr;
            return this->isConnected_;
        }

        bool send(const std::span<uint8_t>& data) noexcept
        {
            if (!isConnected()) {
                return false;
            }

            size_t totalSent = 0;
            while (totalSent < data.size()) {
                const auto sent = ::send(this->socket_.get(), reinterpret_cast<const char*>(data.data() + totalSent),
                    static_cast<int32_t>(data.size() - totalSent), 0
                );

                if (sent == SOCKET_ERROR) {
                    disconnect();
                    return false;
                }

                totalSent += sent;
            }

            return true;
        }

        std::vector<uint8_t> receive(const size_t size)
        {
            if (!isConnected()) {
                return {};
            }

            std::vector<uint8_t> response(size);
            const auto received = recv(this->socket_.get(), reinterpret_cast<char*>(&response[0]), static_cast<int32_t>(size), 0);
            if (received <= 0) {
                disconnect();
                return {};
            }

            response.resize(received);
            return response;
        }

    private:
        bool isInitialized_;
        bool isConnected_;
        scoped_socket::C_ScopedSocket socket_;
        std::wstring address_;
    };

    C_TcpTunnel::C_TcpTunnel(C_TcpTunnel&& other) noexcept : isInitialized_(other.isInitialized_), isConnected_(other.isConnected_), socket_(std::move(other.socket_)), address_(std::move(other.address_))
    {
        other.isInitialized_ = false;
        other.isConnected_ = false;
    }

    C_TcpTunnel& C_TcpTunnel::operator=(C_TcpTunnel&& other) noexcept
    {
        if (this != &other) {
            if (this->isInitialized_) {
                WSACleanup();
            }

            this->isInitialized_ = other.isInitialized_;
            this->isConnected_ = other.isConnected_;
            this->socket_ = std::move(other.socket_);
            this->address_ = std::move(other.address_);

            other.isInitialized_ = false;
            other.isConnected_ = false;
        }
        return *this;
    }
}
