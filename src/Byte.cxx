#include "../aes/Byte.h"

#include <iostream>
#include <bitset>

using namespace AES;
using namespace std;


std::map<Byte, Byte> Byte::s_multiplicative_inverse_map;
Byte  Byte::s_multiplicative_results[256][256];

void Byte::Initialize() {
    InitializeMultiplicationMap();
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

Byte Byte::MultiplyBytes(const Byte& a, const Byte& b)    {
    unsigned short int result = multiply_without_modulo<unsigned short int>(a.m_value, b.m_value);
    result = get_modulo_polynomial(result, s_modulo_polynomial);
    return Byte((unsigned char)(result));
};

void Byte::InitializeMultiplicationMap()    {
    for (unsigned short i = 0; i < 256; i++)    {
        Byte a(i);
        for (unsigned short j = 0; j < 256; j++)    {
            Byte b(j);
            s_multiplicative_results[i][j] = MultiplyBytes(a,b);
        }
    }
};

std::vector<Byte>   AES::get_vector_of_bytes(const std::string &input_string)  {
    const unsigned int length = input_string.length();
    vector<Byte> result;
    result.resize(length);
    for (unsigned int i = 0; i < length; i++)   {
        result[i] = Byte((unsigned char)(input_string[i]));
    }
    return result;
};

std::vector<Byte> AES::get_vector_of_bytes(uint64_t number) {
    std::vector<Byte> result;
    result.resize(8);
    for (unsigned int i = 0; i < 8; i++)   {
        result[7-i] = Byte((unsigned char)(number >> i*8));
    }
    return result;
};
