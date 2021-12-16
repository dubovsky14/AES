#include <iostream>

namespace AES   {
    class Byte  {
        public:
            Byte(unsigned char x);

            char GetValue() const {return m_value;};

            Byte operator+(const Byte& b);

            Byte operator-(const Byte& b);

            Byte operator*(const Byte& b);

            static constexpr short unsigned int s_modulo_polynomial = 0b100011011;

        private:
            unsigned char m_value;


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
    }

    template<class InputType>
    short unsigned int get_index_of_first_non_zero_bit(InputType input) {
        short unsigned int result = 0;
        while (input)   {
            result++;
            input = input >> 1;
        }
        return result;
    }
}