#include "../aes/HelperFunctions.h"

#include<iostream>

using namespace std;
using namespace AES;

void AES::print_out_byte_vector(const std::vector<Byte> &byte_vector)   {
    for (const Byte &byte : byte_vector)    {
        if (byte.GetValue() < 16)   cout << "0";
        cout << std::hex << (unsigned short)(byte.GetValue());
        cout << " ";
    }
};