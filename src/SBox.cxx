#include "../aes/SBox.h"
#include "../aes/Byte.h"


using namespace AES;


std::vector<Byte> SBox::s_S_matrix_lines;
std::vector<Byte> SBox::s_S_inverse_matrix_lines;

void SBox::InitializeSMatrix() {
    s_S_matrix_lines.clear();
    Byte line((unsigned char)(0b00011111));
    for (unsigned int i = 0; i<8; i++)  {
        s_S_matrix_lines.push_back(line);
        line = Byte::circular_bit_shift_left(line, 1);
    }
};


AES::Byte SBox::Encrypt(const AES::Byte &input_byte)  {
//    Byte result(0x63);
//    for (const Byte &matrix_line : s_S_matrix_lines)    {
//        result = result + input_byte*matrix_line;
//    }
//    return result;

    const Byte input_inverse = input_byte.get_inverse();
    return  input_inverse +
            Byte::circular_bit_shift_left(input_inverse, 1)    +
            Byte::circular_bit_shift_left(input_inverse, 2)    +
            Byte::circular_bit_shift_left(input_inverse, 3)    +
            Byte::circular_bit_shift_left(input_inverse, 4)    +
            Byte((unsigned char)(0x63));
};

AES::Byte SBox::Decrypt(const AES::Byte &input_byte)   {
    return  Byte::circular_bit_shift_left(input_byte, 1)    +
            Byte::circular_bit_shift_left(input_byte, 3)    +
            Byte::circular_bit_shift_left(input_byte, 6)    +
            Byte((unsigned char)(0x5));
};
