#pragma once

#include <iostream>
#include <map>
#include <vector>
#include <string>

namespace AES   {
    class Byte  {
        public:
            inline Byte(unsigned char x = 0)   {m_value = x;};

            inline unsigned char GetValue() const {return m_value;};

            inline Byte operator+(const Byte& b)    const   {return Byte(b.m_value ^ m_value);};;

            inline void operator+=(const Byte& b)           {m_value = m_value ^ b.m_value;};

            inline Byte operator-(const Byte& b)    const   {return Byte(b.m_value ^ m_value);};

            inline Byte operator*(const Byte& b)    const   {return s_multiplicative_results[m_value][b.m_value];};

            inline bool operator==(const Byte& b)   const   {return m_value == b.m_value;};
            inline bool operator>(const Byte& b)    const   {return m_value > b.m_value;};
            inline bool operator<(const Byte& b)    const   {return m_value < b.m_value;};

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

            static Byte  s_multiplicative_results[256][256];

            static Byte MultiplyBytes(const Byte& a, const Byte& b);

            static void InitializeMultiplicationMap();


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

    std::vector<Byte> get_vector_of_bytes(uint64_t number);

    template<typename T, typename ... Args>
    std::vector<Byte> get_vector_of_bytes(T x1, Args ... args) {
        std::vector<Byte> result = get_vector_of_bytes(x1);
        std::vector<Byte> args_byte_vector = get_vector_of_bytes(args ...);
        for (const Byte &x : args_byte_vector)    {
            result.push_back(x);
        }
        return result;
    };
}