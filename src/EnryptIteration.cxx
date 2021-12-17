#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/EncryptIteration.h"

using namespace AES;


Byte EncryptIteration::s_mix_column_matrix[4][4] {
    {Byte(2), Byte(3), Byte(1), Byte(1)},
    {Byte(1), Byte(2), Byte(3), Byte(1)},
    {Byte(1), Byte(1), Byte(2), Byte(3)},
    {Byte(3), Byte(1), Byte(1), Byte(2)},
};

Byte EncryptIteration::s_mix_matrix_temp_result[4];

void EncryptIteration::Encrypt(Byte *array_of_16_bytes, const Byte *subkey)  {
    SubstituteBytes(array_of_16_bytes);
    ShiftRows(array_of_16_bytes);
    MixColumns(array_of_16_bytes);
    AddKey(array_of_16_bytes, subkey);
};

void EncryptIteration::SubstituteBytes(Byte *array_of_16_bytes)   {
    for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
        array_of_16_bytes[i_byte] = SBox::Encrypt(array_of_16_bytes[i_byte]);
    }
};

void EncryptIteration::ShiftRows(Byte *array_of_16_bytes) {
    AES::Byte result[16];
    for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
        result[i_byte] = array_of_16_bytes[(i_byte*5) % 16];
    }
    for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
        array_of_16_bytes[i_byte] = result[i_byte];
    }
};

void EncryptIteration::MixColumns(Byte *array_of_16_bytes)    {
    for (unsigned int i_4bytes_group = 0; i_4bytes_group < 4; i_4bytes_group++)  {
        ApplyMixMatrix(&array_of_16_bytes[i_4bytes_group*4]);
    }

};

void EncryptIteration::ApplyMixMatrix(Byte *array_of_4_bytes)   {
    for (unsigned int i = 0; i < 4; i++)    {
        s_mix_matrix_temp_result[i] = Byte(0);
        for (unsigned int j = 0; j < 4; j++)    {
            s_mix_matrix_temp_result[i] += s_mix_column_matrix[i][j]*array_of_4_bytes[j];
        }
    }
    for (unsigned int i = 0; i < 4; i++)    {
        array_of_4_bytes[i] = s_mix_matrix_temp_result[i];
    }
}

void EncryptIteration::AddKey(Byte *array_of_16_bytes, const Byte *subkey)    {
    for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
        array_of_16_bytes[i_byte] = array_of_16_bytes[i_byte] + subkey[i_byte];
    }
};
