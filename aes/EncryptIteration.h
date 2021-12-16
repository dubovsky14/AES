#pragma once

#include "../aes/Byte.h"

#include<vector>

namespace AES   {
    class EncryptIteration  {
        public:
            static void Encrypt(Byte *array_of_16_bytes, const Byte *subkey);

        //private:
            static void SubstituteBytes(Byte *array_of_16_bytes);

            static void ShiftRows(Byte *array_of_16_bytes);

            static void MixColumns(Byte *array_of_16_bytes);

            static void ApplyMixMatrix(Byte *array_of_4_bytes);

            static void AddKey(Byte *array_of_16_bytes, const Byte *subkey);

            static Byte s_mix_column_matrix[4][4];

            static Byte s_mix_matrix_temp_result[4];
    };
}