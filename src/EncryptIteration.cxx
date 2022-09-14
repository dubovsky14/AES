#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/EncryptIteration.h"

#include <iostream>
#include <cstdint>
#include <cstring>
#include <algorithm>

using namespace AES;



Byte EncryptIteration::s_mix_column_matrix[4][4] {
    {Byte(2), Byte(3), Byte(1), Byte(1)},
    {Byte(1), Byte(2), Byte(3), Byte(1)},
    {Byte(1), Byte(1), Byte(2), Byte(3)},
    {Byte(3), Byte(1), Byte(1), Byte(2)},
};

Byte EncryptIteration::s_mix_column_matrix_inverse[4][4] {
    {Byte((unsigned char)(0x0e)), Byte((unsigned char)(0x0b)), Byte((unsigned char)(0x0d)), Byte((unsigned char)(0x09))},
    {Byte((unsigned char)(0x09)), Byte((unsigned char)(0x0e)), Byte((unsigned char)(0x0b)), Byte((unsigned char)(0x0d))},
    {Byte((unsigned char)(0x0d)), Byte((unsigned char)(0x09)), Byte((unsigned char)(0x0e)), Byte((unsigned char)(0x0b))},
    {Byte((unsigned char)(0x0b)), Byte((unsigned char)(0x0d)), Byte((unsigned char)(0x09)), Byte((unsigned char)(0x0e))},
};

void EncryptIteration::Decrypt(Byte *array_of_16_bytes, const Byte *subkey, bool mix_columns)  {
    AddKey(array_of_16_bytes, subkey);
    if (mix_columns)    {
        MixColumns(array_of_16_bytes, true);
    }
    ShiftRows(array_of_16_bytes, true);
    SubstituteBytesDecryption(array_of_16_bytes);
};

void EncryptIteration::Encrypt(Byte *array_of_16_bytes, const Byte *subkey, bool mix_columns)  {
    SubstituteBytesEncryption(array_of_16_bytes);
    ShiftRows(array_of_16_bytes);
    if (mix_columns)    {
        MixColumns(array_of_16_bytes);
    }
    AddKey(array_of_16_bytes, subkey);
};

void EncryptIteration::SubstituteBytesEncryption(Byte *array_of_16_bytes)   {
    for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
        array_of_16_bytes[i_byte] = SBox::Encrypt(array_of_16_bytes[i_byte]);
    }
};

void EncryptIteration::SubstituteBytesDecryption(Byte *array_of_16_bytes)   {
    for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
        array_of_16_bytes[i_byte] = SBox::Decrypt(array_of_16_bytes[i_byte]);
    }
};

void EncryptIteration::ShiftRows(Byte *array_of_16_bytes, bool inverse) {
    AES::Byte result[16];
    if (!inverse)    {
        for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
            result[i_byte] = array_of_16_bytes[(i_byte*5) % 16];
        }
    }
    else {
        for (unsigned int i_byte = 0; i_byte < 16; i_byte++)    {
            result[(i_byte*5) % 16] = array_of_16_bytes[i_byte];
        }
    }

    memcpy( array_of_16_bytes, result, 16 );
};

void EncryptIteration::AddKey(Byte *array_of_16_bytes, const Byte *subkey)    {
    std::transform( reinterpret_cast<unsigned long long int *> (array_of_16_bytes),
                    reinterpret_cast<unsigned long long int *> (array_of_16_bytes+16),
                    reinterpret_cast<const unsigned long long int *> (subkey),
                    reinterpret_cast<unsigned long long int *> (array_of_16_bytes),
                    std::bit_xor ());
};
