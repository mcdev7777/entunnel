//
// Created by sexey on 20.01.2026.
//
module;
#include <string>
#include <string_view>
#include <windows.h>
#include <cstdint>
#include <optional>
#include <sspi.h>
#include <security.h>
#include <vector>

export module entunnel.sspi_auth;
import entunnel.base64;

export namespace entunnel::win::sspi
{
    class C_SSPI
    {
    public:
        struct auth_result_s
        {
            bool needContinue;
            std::string token;
            bool isCompleted;
        };

        ~C_SSPI() { cleanup(); }
        C_SSPI() = default;
        C_SSPI(const C_SSPI&) = delete;
        C_SSPI& operator=(const C_SSPI&) = delete;
        C_SSPI(C_SSPI&&) noexcept = default;
        C_SSPI& operator=(C_SSPI&&) noexcept = default;

        [[nodiscard]] const std::string& scheme() const noexcept { return this->scheme_; }
        [[nodiscard]] bool isInitialized() const noexcept { return this->isCredentialsAcquired_; }

        [[nodiscard]] bool initialize(const std::string_view& authScheme, const std::string_view& proxyAddress)
        {
            if (this->isCredentialsAcquired_) {
                return true;
            }

            this->scheme_ = authScheme;
            this->address_ = proxyAddress;

            const auto status = AcquireCredentialsHandleA(
                nullptr,
                const_cast<char*>(this->scheme_.c_str()),
                SECPKG_CRED_OUTBOUND,
                nullptr, nullptr, nullptr, nullptr,
                &this->credentials_,
                nullptr
            );

            if (status != SEC_E_OK) {
                return false;
            }

            this->isCredentialsAcquired_ = true;
            return true;
        }

        [[nodiscard]] std::optional<auth_result_s> processChallenge(const std::string_view& challenge)
        {
            if (!isInitialized()) {
                return std::nullopt;
            }

            SecBufferDesc* pInput = nullptr;
            SecBufferDesc inputDescriptor{};
            SecBuffer inputBuffer{};
            std::vector<uint8_t> serverToken;

            if (!challenge.empty()) {
                serverToken = encoding::base64::Decode(challenge.data());
                if (serverToken.empty()) {
                    return std::nullopt;
                }

                inputBuffer = {
                    .cbBuffer = static_cast<ULONG>(serverToken.size()),
                    .BufferType = SECBUFFER_TOKEN,
                    .pvBuffer = serverToken.data()
                };

                inputDescriptor = {
                    .ulVersion = SECBUFFER_VERSION,
                    .cBuffers = 1,
                    .pBuffers = &inputBuffer
                };

                pInput = &inputDescriptor;
            }

            SecBuffer outputBuffer = {
                .cbBuffer = 0,
                .BufferType = SECBUFFER_TOKEN,
                .pvBuffer = nullptr
            };

            SecBufferDesc outputDescriptor = {
                .ulVersion = SECBUFFER_VERSION,
                .cBuffers = 1,
                .pBuffers = &outputBuffer
            };

            ULONG contextAttr = 0;
            TimeStamp tsExpiry{};

            const PCtxtHandle phContext = this->isCreatedContext_ ? &this->context_ : nullptr;

            const std::string spn = "HTTP/" + this->address_;
            char* pszTargetName = this->isCreatedContext_ ? nullptr : const_cast<char*>(spn.c_str());

            const SECURITY_STATUS status = InitializeSecurityContextA(
                &this->credentials_,
                phContext,
                pszTargetName,
                ISC_REQ_CONNECTION | ISC_REQ_ALLOCATE_MEMORY,
                0,
                SECURITY_NATIVE_DREP,
                pInput,
                0,
                &this->context_,
                &outputDescriptor,
                &contextAttr,
                &tsExpiry
            );

            if (status != SEC_E_OK && status != SEC_I_CONTINUE_NEEDED) {
                return std::nullopt;
            }

            this->isCreatedContext_ = true;

            auth_result_s result{
                .needContinue = (status == SEC_I_CONTINUE_NEEDED),
                .token = {},
                .isCompleted = (status == SEC_E_OK)
            };

            if (outputBuffer.pvBuffer && outputBuffer.cbBuffer > 0) {
                result.token = encoding::base64::Encode({
                    static_cast<uint8_t*>(outputBuffer.pvBuffer),
                    outputBuffer.cbBuffer
                });
                FreeContextBuffer(outputBuffer.pvBuffer);
            }

            return result;
        }

    private:
        void cleanup()
        {
            if (this->isCredentialsAcquired_) {
                FreeCredentialsHandle(&this->credentials_);
                this->isCredentialsAcquired_ = false;
            }

            if (this->isCreatedContext_) {
                DeleteSecurityContext(&this->context_);
                this->isCreatedContext_ = false;
            }
        }

        bool isCredentialsAcquired_ = false;
        bool isCreatedContext_ = false;
        std::string scheme_;
        std::string address_;
        CtxtHandle context_{};
        CredHandle credentials_{};
    };
}