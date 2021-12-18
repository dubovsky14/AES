#include "../aes/SBox.h"
#include "../aes/Byte.h"

#include <iostream>

using namespace AES;

std::vector<Byte> SBox::s_sbox_encrypt;
std::vector<Byte> SBox::s_sbox_decrypt;

void SBox::Initialize()   {
    s_sbox_decrypt.resize(256);
    s_sbox_encrypt.resize(256);
    for (unsigned short i = 0; i < 256; i++)    {
        Byte input_byte(i);
        const Byte input_inverse = input_byte.get_inverse();
        const Byte encrypted_byte =
                input_inverse +
                Byte::circular_bit_shift_left(input_inverse, 1)    +
                Byte::circular_bit_shift_left(input_inverse, 2)    +
                Byte::circular_bit_shift_left(input_inverse, 3)    +
                Byte::circular_bit_shift_left(input_inverse, 4)    +
                Byte((unsigned char)(0x63));
        s_sbox_decrypt[encrypted_byte.GetValue()]  = input_byte;
        s_sbox_encrypt[input_byte.GetValue()]      = encrypted_byte;
    }
};
