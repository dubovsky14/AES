#include "../aes/HelperFunctions.h"

#include<iostream>
#include<algorithm>

using namespace std;
using namespace AES;

void AES::print_out_byte_vector(const std::vector<Byte> &byte_vector)   {
    for (const Byte &byte : byte_vector)    {
        if (byte.GetValue() < 16)   cout << "0";
        cout << std::hex << (unsigned short)(byte.GetValue());
        cout << " ";
    }
};

void         AES::to_upper(std::string *input_string) {
    std::transform(input_string->begin(), input_string->end(),input_string->begin(), ::toupper);
};

std::string  AES::to_upper_copy(const std::string &input_string)  {
    string result = input_string;
    AES::to_upper(&result);
    return result;
};
