#pragma once

#include <vector>

#include "../aes/Byte.h"

namespace AES   {
    class SBox    {
        public:
            static Byte Encrypt(const Byte &input_byte);

            static Byte Decrypt(const Byte &input_byte);

        private:
    };
}