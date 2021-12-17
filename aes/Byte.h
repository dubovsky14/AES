#pragma once

#include <iostream>
#include <map>
#include <vector>
#include <string>

namespace AES   {
    class Byte  {
        public:
            Byte(unsigned char x = 0);

            unsigned char GetValue() const {return m_value;};

            Byte operator+(const Byte& b)   const;

            void operator+=(const Byte& b);

            Byte operator-(const Byte& b)   const;

            Byte operator*(const Byte& b)   const;

            bool operator==(const Byte& b)    const;
            bool operator>(const Byte& b)    const  {return m_value > b.m_value;};
            bool operator<(const Byte& b)    const  {return m_value < b.m_value;};

            static void Initialize();

            Byte get_inverse()  const   {return s_multiplicative_inverse_map[*this];};

            static constexpr short unsigned int s_modulo_polynomial = 0b100011011;

            static unsigned char circular_bit_shift_left(const unsigned char &input, unsigned int shift_size);

            static unsigned char circular_bit_shift_right(const unsigned char &input, unsigned int shift_size);

            static Byte circular_bit_shift_left(const Byte &input, unsigned int shift_size);

            static Byte circular_bit_shift_right(const Byte &input, unsigned int shift_size);

            static unsigned short get_modulo_polynomial(unsigned short numerator, unsigned short denominator);

        private:
            unsigned char m_value;

            static std::map<Byte, Byte> s_multiplicative_inverse_map;


    };
    template<class OutputType>
    OutputType multiply_without_modulo(unsigned char a, unsigned char b) {
        OutputType result = 0;
        // (can't use m_value*b.m_value because the coefficients are from GF(2)):
        unsigned char multiplier = 0b10000000;
        while (multiplier > 0)    {
            if (multiplier & a)   {
                result = result ^ (OutputType)(multiplier * b);
            }
            multiplier = multiplier >> 1;
        }
        return result;
    };

    template<class InputType>
    short unsigned int get_index_of_first_non_zero_bit(InputType input) {
        short unsigned int result = 0;
        while (input)   {
            result++;
            input = input >> 1;
        }
        return result;
    };

    std::vector<Byte>   get_vector_of_bytes(const std::string &input_string);

    std::vector<Byte>   get_vector_of_bytes(uint64_t first_half, uint64_t second_half);
}