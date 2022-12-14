#pragma once

#include "../aes/Byte.h"
#include "../aes/KeyScheduler.h"

#include <vector>
#include <memory>

namespace AES   {
    class AESHandler    {
        public:
            AESHandler(uint64_t key_first_half, uint64_t key_second_half);

            AESHandler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3);

            AESHandler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3, uint64_t key_part4);

            AESHandler(const std::vector<Byte> &key);

            AESHandler(const unsigned char *key, unsigned int key_size_bits);

            void Encrypt(Byte *text)  const;
            void Encrypt(const Byte *plain_text, Byte *cipher_text) const;

            void Encrypt(unsigned char *text)  const;
            void Encrypt(const unsigned char *plain_text, unsigned char *cipher_text) const;

            void Decrypt(Byte *text)  const;
            void Decrypt(const Byte *cipher_text, Byte *plain_text)   const;

            void Decrypt(unsigned char *text)  const;
            void Decrypt(const unsigned char *cipher_text, unsigned char *plain_text) const;

            static std::vector<Byte> GetByteVector(const std::string &input_text);

        private:
            std::shared_ptr<KeyScheduler> m_key_scheduler    = nullptr;

            void Initialize(const std::vector<Byte> &key);

            template<class ValueType>
            static void copy_array(const ValueType *source, ValueType *target, size_t n_elements) {
                for (size_t i = 0; i < n_elements; i++) {
                    target[i] = source[i];
                }
            }

            unsigned int m_number_of_iterations = 10;
    };
}