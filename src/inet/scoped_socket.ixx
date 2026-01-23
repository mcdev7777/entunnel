//
// Created by sexey on 19.01.2026.
//
module;
#include <winsock2.h>

export module entunnel.scoped_socket;

export namespace entunnel::inet::scoped_socket
{
    class C_ScopedSocket
    {
    public:
        ~C_ScopedSocket() { close(); }

        C_ScopedSocket() noexcept : sock_(INVALID_SOCKET) {}
        explicit C_ScopedSocket(SOCKET s) noexcept : sock_(s) {}

        C_ScopedSocket(const C_ScopedSocket&) = delete;
        C_ScopedSocket& operator=(const C_ScopedSocket&) = delete;

        C_ScopedSocket(C_ScopedSocket&& other) noexcept : sock_(other.sock_) {
            other.sock_ = INVALID_SOCKET;
        }

        C_ScopedSocket& operator=(C_ScopedSocket&& other) noexcept {
            if (this != &other) {
                close();
                this->sock_ = other.sock_;
                other.sock_ = INVALID_SOCKET;
            }
            return *this;
        }

        [[nodiscard]] bool isValid() const noexcept { return this->sock_ != INVALID_SOCKET; }

        [[nodiscard]] SOCKET get() const noexcept { return this->sock_; }

        [[nodiscard]] SOCKET release() noexcept
        {
            const SOCKET temp = this->sock_;
            this->sock_ = INVALID_SOCKET;

            return temp;
        }

        void close() noexcept
        {
            if (this->sock_ != INVALID_SOCKET) {
                closesocket(this->sock_);
                this->sock_ = INVALID_SOCKET;
            }
        }

        void reset(SOCKET s = INVALID_SOCKET) noexcept
        {
            close();
            this->sock_ = s;
        }

    private:
        SOCKET sock_;
    };
}