#include "../aes/Byte.h"

#include <iostream>

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
    unsigned short int result = 0;
    // firstly perform the multiplication without the modulo (can't use m_value*b.m_value because the coefficients are from GF(2)):
    unsigned char multiplier = 0b10000000;
    while (multiplier > 0)    {
        if (multiplier & m_value)   {
            result = result ^ (unsigned short int)(multiplier * b.m_value);
        }
        multiplier = multiplier >> 1;
    }

    //unsigned short int mod_temp = s_modulo_polynomial*0b10000000;
    //while (result > 255)    {
    //    while (mod_temp > result)  {
    //        mod_temp /= 2;
    //    }
    //    result = result ^ mod_temp;
    //}
    return Byte((unsigned char)(result));
};