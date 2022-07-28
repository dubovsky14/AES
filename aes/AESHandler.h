#pragma once

#include "../aes/Byte.h"
#include "../aes/KeyScheduler128.h"

#include <vector>

namespace AES   {
    class AESHandler    {
        public:
            AESHandler(uint64_t key_first_half, uint64_t key_second_half);

            AESHandler(const std::vector<Byte> &key);

            ~AESHandler();

            void Encrypt(Byte *text)  const;
            void Encrypt(const Byte *plain_text, Byte *cipher_text) const;

            void Decrypt(Byte *text)  const;
            void Decrypt(const Byte *cipher_text, Byte *plain_text)   const;

            static std::vector<Byte> GetByteVector(const std::string &input_text);

        private:
            KeyScheduler128 *m_key_scheduler    = nullptr;

            template<class ValueType>
            static void copy_array(const ValueType *source, ValueType *target, size_t n_elements) {
                for (size_t i = 0; i < n_elements; i++) {
                    target[i] = source[i];
                }
            }
    };
}