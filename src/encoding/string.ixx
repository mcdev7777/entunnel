//
// Created by sexey on 23.01.2026.
//
module;
#include <cstdint>
#include <string>
#include <windows.h>

export module entunnel.encoding;

namespace entunnel::encoding::string
{
    export std::string ToUtf8(const std::wstring_view& str)
    {
        if (str.empty()) {
            return {};
        }

        const int32_t size = WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), nullptr, 0, nullptr, nullptr);
        if (!size) {
            return {};
        }

        std::string output(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, str.data(), str.size(), output.data(), size, nullptr, nullptr);

        return output;
    }
}
