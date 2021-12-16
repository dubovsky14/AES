#pragma once

#include <vector>

#include "../aes/Byte.h"

namespace AES   {
    class SBox    {
        public:
            static Byte Encrypt(const Byte &input_byte);

            static Byte Decrypt(const Byte &input_byte);

            static void InitializeSMatrix();

        private:
            static std::vector<Byte> s_S_matrix_lines;
            static std::vector<Byte> s_S_inverse_matrix_lines;
    };
}