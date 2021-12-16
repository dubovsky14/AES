#include "../aes/Byte.h"

#include <iostream>
#include <bitset>

using namespace AES;
using namespace std;

Byte::Byte(unsigned char x) {
    m_value = x;
};

Byte Byte::operator+(const Byte& b) {
    return Byte(b.m_value ^ m_value);
};

Byte Byte::operator-(const Byte& b) {
    return Byte(b.m_value ^ m_value);
};


Byte Byte::operator*(const Byte& b) {
    unsigned short int result = multiply_without_modulo<unsigned short int>(m_value, b.m_value);
    unsigned short int first_non_zero_bit_result = get_index_of_first_non_zero_bit(result);
    unsigned short int first_non_zero_bit_modulo = get_index_of_first_non_zero_bit(s_modulo_polynomial);

    while (first_non_zero_bit_result >= first_non_zero_bit_modulo)    {
        const unsigned short int temp_modulo = s_modulo_polynomial << (first_non_zero_bit_result - first_non_zero_bit_modulo);
        result = temp_modulo ^ result;
        first_non_zero_bit_result = get_index_of_first_non_zero_bit(result);
    }
    return Byte((unsigned char)(result));
};