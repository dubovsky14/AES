#pragma once

#include "../aes/Byte.h"

#include<vector>
#include <cstring>

namespace AES   {
    class EncryptIteration  {
        public:
            static void Encrypt(Byte *array_of_16_bytes, const Byte *subkey, bool mix_columns);

            static void Decrypt(Byte *array_of_16_bytes, const Byte *subkey, bool mix_columns);

        //private:
            static void SubstituteBytesEncryption(Byte *array_of_16_bytes);

            static void SubstituteBytesDecryption(Byte *array_of_16_bytes);

            static void ShiftRows(Byte *array_of_16_bytes, bool inverse = false);

            inline static void MixColumns(Byte *array_of_16_bytes, bool inverse = false)    {
                for (unsigned int i_4bytes_group = 0; i_4bytes_group < 4; i_4bytes_group++)  {
                    if (!inverse)   {
                        ApplyMixMatrixEncryption(&array_of_16_bytes[i_4bytes_group*4]);
                    }
                    else {
                        ApplyMixMatrixDecryption(&array_of_16_bytes[i_4bytes_group*4]);
                    }
                }
            };

            inline static void ApplyMixMatrixEncryption(Byte *array_of_4_bytes)    {
                Byte mix_matrix_temp_result[4];
                for (unsigned int i = 0; i < 4; i++)    {
                    mix_matrix_temp_result[i] = Byte(0);
                    for (unsigned int j = 0; j < 4; j++)    {
                        mix_matrix_temp_result[i] += s_mix_column_matrix[i][j]*array_of_4_bytes[j];
                    }
                }
                std::memcpy( array_of_4_bytes, mix_matrix_temp_result, 4 );
            };

            inline static void ApplyMixMatrixDecryption(Byte *array_of_4_bytes)    {
                Byte mix_matrix_temp_result[4];
                for (unsigned int i = 0; i < 4; i++)    {
                    mix_matrix_temp_result[i] = Byte(0);
                    for (unsigned int j = 0; j < 4; j++)    {
                        mix_matrix_temp_result[i] += s_mix_column_matrix_inverse[i][j]*array_of_4_bytes[j];
                    }
                }
                for (unsigned int i = 0; i < 4; i++)    {
                    array_of_4_bytes[i] = mix_matrix_temp_result[i];
                }
            };

            static void AddKey(Byte *array_of_16_bytes, const Byte *subkey);

            static Byte s_mix_column_matrix[4][4];

            static Byte s_mix_column_matrix_inverse[4][4];

    };
}