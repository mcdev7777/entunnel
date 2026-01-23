//
// Created by sexey on 20.01.2026.
//
module;
#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

export module entunnel.base64;

export namespace entunnel::encoding::base64
{
    std::string Encode(const std::span<uint8_t>& data)
    {
        if (data.empty()) {
            return std::string();
        }

        DWORD dwSize = 0;
        CryptBinaryToStringA(
            data.data(),
            data.size(),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr,
            &dwSize
        );

        if (dwSize == 0) {
            return std::string();
        }

        std::string result(dwSize, '\0');
        CryptBinaryToStringA(
            data.data(),
            data.size(),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            &result[0],
            &dwSize
        );

        return result;
    }

    std::vector<uint8_t> Decode(const std::string& base64)
    {
        if (base64.empty()) {
            return std::vector<uint8_t>();
        }

        DWORD dwSize = 0;
        if (!CryptStringToBinaryA(
            base64.c_str(),
            base64.length(),
            CRYPT_STRING_BASE64,
            nullptr,
            &dwSize,
            nullptr,
            nullptr))
        {
            return std::vector<uint8_t>();
        }

        std::vector<uint8_t> result(dwSize);
        if (!CryptStringToBinaryA(
            base64.c_str(),
            base64.length(),
            CRYPT_STRING_BASE64,
            result.data(),
            &dwSize,
            nullptr,
            nullptr))
        {
            return std::vector<uint8_t>();
        }

        return result;
    }
}