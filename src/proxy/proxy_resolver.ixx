//
// Created by sexey on 19.01.2026.
//
module;
#include <cstdint>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <windows.h>
#include <winhttp.h>
#include <versionhelpers.h>

export module entunnel.proxy;

namespace entunnel::proxy
{
    struct winhttp_proxy_info_s : public WINHTTP_PROXY_INFO
    {
        ~winhttp_proxy_info_s()
        {
            if (this->lpszProxy) {
                GlobalFree(this->lpszProxy);
            }

            if (this->lpszProxyBypass) {
                GlobalFree(this->lpszProxyBypass);
            }
        }
    };

    struct winhttp_ie_proxy_info_s : public WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
    {
        winhttp_ie_proxy_info_s() = default;
        ~winhttp_ie_proxy_info_s() { dispose(); }

        winhttp_ie_proxy_info_s(const winhttp_ie_proxy_info_s&) = delete;
        winhttp_ie_proxy_info_s& operator=(const winhttp_ie_proxy_info_s&) = delete;

        winhttp_ie_proxy_info_s(winhttp_ie_proxy_info_s&& other) noexcept
            : WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(other)
        {
            other.lpszAutoConfigUrl = nullptr;
            other.lpszProxy = nullptr;
            other.lpszProxyBypass = nullptr;
        }

        winhttp_ie_proxy_info_s& operator=(winhttp_ie_proxy_info_s&& other) noexcept
        {
            if (this != &other) {
                dispose();

                // Переносим ресурсы
                WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::operator=(other);
                other.lpszAutoConfigUrl = nullptr;
                other.lpszProxy = nullptr;
                other.lpszProxyBypass = nullptr;
            }

            return *this;
        }

        void dispose()
        {
            if (this->lpszAutoConfigUrl) {
                GlobalFree(this->lpszAutoConfigUrl);
            }

            if (this->lpszProxy) {
                GlobalFree(this->lpszProxy);
            }

            if (this->lpszProxyBypass) {
                GlobalFree(this->lpszProxyBypass);
            }
        }
    };

    struct galloc_destructor_s
    {
        void operator()(wchar_t* ptr) const noexcept
        {
            if (ptr) {
                GlobalFree(ptr);
            }
        }
    };

    struct winhttp_autoproxy_s : public WINHTTP_AUTOPROXY_OPTIONS
    {
        std::unique_ptr<wchar_t, galloc_destructor_s> ieProxyFallback;
        std::unique_ptr<wchar_t, galloc_destructor_s> autoConfigUrlOwner;
    };

    struct proxy_info_s
    {
        std::wstring addr;
        uint16_t port{0};
    };

    std::optional<proxy_info_s> ParseProxyString(const std::wstring_view& proxyList)
    {
        std::wstring proxyString;
        if (const auto listDelimiter = proxyList.find_first_of(L"; "); listDelimiter != std::wstring::npos) {
            proxyString = proxyList.substr(0, listDelimiter);
        } else {
            proxyString = proxyList;
        }

        const auto delimiterPos = proxyString.rfind(L':');
        if (delimiterPos == std::wstring::npos) {
            return std::nullopt;
        }

        const wchar_t* portStart = proxyString.c_str() + delimiterPos + 1;
        wchar_t* portEnd = nullptr;

        const unsigned long portVal = std::wcstoul(portStart, &portEnd, 10);
        if (portStart == portEnd || *portEnd != L'\0') {
            return std::nullopt;
        }

        return proxy_info_s{
            .addr = proxyString.substr(0, delimiterPos),
            .port = static_cast<uint16_t>(portVal)
        };
    }

    std::optional<winhttp_ie_proxy_info_s> GetInternetExplorerProxy()
    {
        winhttp_ie_proxy_info_s proxyInfo;
        if (!WinHttpGetIEProxyConfigForCurrentUser(&proxyInfo)) {
            return std::nullopt;
        }

        return proxyInfo;
    }

    void ConfigurateProxyResolverOptions(winhttp_autoproxy_s& options)
    {
        auto defaultOpts = [](winhttp_autoproxy_s& opts) {
            opts.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
            opts.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
        };

        if (auto ieProxy = GetInternetExplorerProxy(); ieProxy.has_value()) {
            auto& info = ieProxy.value();
            if (info.fAutoDetect && !info.lpszAutoConfigUrl) {
                defaultOpts(options);
            } else {
                options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
                options.autoConfigUrlOwner.reset(info.lpszAutoConfigUrl);
                options.lpszAutoConfigUrl = std::exchange(info.lpszAutoConfigUrl, nullptr);
            }

            if (info.lpszProxy) { // for fallback
                options.ieProxyFallback.reset(std::exchange(info.lpszProxy, nullptr));
            }
        } else {
            defaultOpts(options);
        }

        options.fAutoLogonIfChallenged = TRUE;
    }

    bool WinHttpProxyResolve(const std::wstring_view& url, winhttp_autoproxy_s& options, winhttp_proxy_info_s& proxyInfo)
    {
        static auto session{WinHttpOpen(nullptr,
            (IsWindows8Point1OrGreater()) ? WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0
        )};

        if (!session) {
            return false;
        }

        if (const bool resolverResult = WinHttpGetProxyForUrl(session, url.data(), &options, &proxyInfo);
            !resolverResult || proxyInfo.dwAccessType != WINHTTP_ACCESS_TYPE_NAMED_PROXY || !proxyInfo.lpszProxy) {
            if (!options.ieProxyFallback) {
                return false;
            }

            proxyInfo.lpszProxy = options.ieProxyFallback.release();
        }

        return true;
    }

    export std::optional<proxy_info_s> GetSystemProxyForUrl(const std::wstring_view& address)
    {
        winhttp_autoproxy_s autoProxyOptions{};
        ConfigurateProxyResolverOptions(autoProxyOptions);

        winhttp_proxy_info_s proxyInfo{};
        if (!WinHttpProxyResolve(std::format(L"https://{}/", address), autoProxyOptions, proxyInfo)) {
            return std::nullopt;
        }

        return ParseProxyString(proxyInfo.lpszProxy);
    }
}