#pragma once

#include "../aes/Byte.h"

#include <vector>
#include <map>

namespace AES   {
    class SBox    {
        public:
            static Byte Encrypt(const Byte &input_byte);

            static Byte Decrypt(const Byte &input_byte);

            static void Initialize();

        private:
            static std::vector<Byte> s_sbox_encrypt;

            static std::vector<Byte> s_sbox_decrypt;
    };
}