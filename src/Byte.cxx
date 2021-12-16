#include "../aes/Byte.h"

#include <iostream>
#include <bitset>

using namespace AES;
using namespace std;


std::map<Byte, Byte> Byte::s_multiplicative_inverse_map;

void Byte::Initialize() {
    s_multiplicative_inverse_map[Byte((unsigned char)(0))] = Byte((unsigned char)(0));
    for (unsigned char i = 1; i != 0; i++)    {
        // looking for inverse element
        Byte current_byte(i);
        for (unsigned char j = 1; j != 0; j++)    {
            Byte result = current_byte*Byte(j);
            if (result == Byte(1))  {
                s_multiplicative_inverse_map[Byte(j)] = Byte(i);
            }
        }
    }
}

Byte::Byte(unsigned char x) {
    m_value = x;
};

Byte Byte::operator+(const Byte& b)  const {
    return Byte(b.m_value ^ m_value);
};

Byte Byte::operator-(const Byte& b)  const {
    return Byte(b.m_value ^ m_value);
};

Byte Byte::operator*(const Byte& b)  const {
    unsigned short int result = multiply_without_modulo<unsigned short int>(m_value, b.m_value);
    result = get_modulo_polynomial(result, s_modulo_polynomial);
    return Byte((unsigned char)(result));
};

bool Byte::operator==(const Byte& b)    const {
    return m_value == b.m_value;
};

unsigned short Byte::get_modulo_polynomial(unsigned short numerator, unsigned short denominator)  {
    unsigned short int result = numerator;
    unsigned short int first_non_zero_bit_result = get_index_of_first_non_zero_bit(result);
    unsigned short int first_non_zero_bit_modulo = get_index_of_first_non_zero_bit(denominator);

    while (first_non_zero_bit_result >= first_non_zero_bit_modulo)    {
        const unsigned short int temp_modulo = denominator << (first_non_zero_bit_result - first_non_zero_bit_modulo);
        result = temp_modulo ^ result;
        first_non_zero_bit_result = get_index_of_first_non_zero_bit(result);
    }
    return result;
};

unsigned char Byte::circular_bit_shift_left(const unsigned char &input, unsigned int shift_size)    {
    return (unsigned char)((input << shift_size) | (input >> (8-shift_size)));
}

unsigned char Byte::circular_bit_shift_right(const unsigned char &input, unsigned int shift_size)   {
    return (unsigned char)((input >> shift_size) | (input << (8-shift_size)));
}

Byte Byte::circular_bit_shift_left(const Byte &input, unsigned int shift_size)    {
    return Byte(circular_bit_shift_left(input.m_value, shift_size));
};

Byte Byte::circular_bit_shift_right(const Byte &input, unsigned int shift_size)    {
    return Byte(circular_bit_shift_right(input.m_value, shift_size));
};