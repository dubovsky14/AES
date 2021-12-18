#pragma once

#include "../aes/Byte.h"

#include<vector>

namespace AES   {
    class EncryptIteration  {
        public:
            static void Encrypt(Byte *array_of_16_bytes, const Byte *subkey, bool mix_columns);

            static void Decrypt(Byte *array_of_16_bytes, const Byte *subkey, bool mix_columns);

        //private:
            static void SubstituteBytesEncryption(Byte *array_of_16_bytes);

            static void SubstituteBytesDecryption(Byte *array_of_16_bytes);

            static void ShiftRows(Byte *array_of_16_bytes, bool inverse = false);

            static void MixColumns(Byte *array_of_16_bytes, bool inverse = false);

            static void ApplyMixMatrixEncryption(Byte *array_of_4_bytes);

            static void ApplyMixMatrixDecryption(Byte *array_of_4_bytes);

            static void AddKey(Byte *array_of_16_bytes, const Byte *subkey);

            static Byte s_mix_column_matrix[4][4];

            static Byte s_mix_column_matrix_inverse[4][4];

    };
}