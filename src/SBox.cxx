#include "../aes/SBox.h"
#include "../aes/Byte.h"


using namespace AES;

AES::Byte SBox::Encrypt(const AES::Byte &input_byte)  {
    const Byte input_inverse = input_byte.get_inverse();
    return  input_inverse +
            Byte::circular_bit_shift_left(input_inverse, 1)    +
            Byte::circular_bit_shift_left(input_inverse, 2)    +
            Byte::circular_bit_shift_left(input_inverse, 3)    +
            Byte::circular_bit_shift_left(input_inverse, 4)    +
            Byte((unsigned char)(0x63));
};

AES::Byte SBox::Decrypt(const AES::Byte &input_byte)   {
    return  (Byte::circular_bit_shift_left(input_byte, 1)    +
            Byte::circular_bit_shift_left(input_byte, 3)    +
            Byte::circular_bit_shift_left(input_byte, 6)    +
            Byte((unsigned char)(0x5))).get_inverse();
};
