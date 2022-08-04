#pragma once

#include "../aes/Byte.h"

#include <vector>

namespace AES   {
    class SBox    {
        public:
            inline static Byte Encrypt(const Byte &input_byte)  {return s_sbox_encrypt[input_byte.GetValue()];};

            inline static Byte Decrypt(const Byte &input_byte)  {return s_sbox_decrypt[input_byte.GetValue()];};

            static void Initialize();

        private:
            static std::vector<Byte> s_sbox_encrypt;

            static std::vector<Byte> s_sbox_decrypt;
    };
}