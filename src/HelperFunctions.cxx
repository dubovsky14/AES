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

std::vector<Byte>   AES::GetKeyByteVector(const std::string &key_string) {
    vector<Byte> key            = get_vector_of_bytes(key_string);
    if (key.size() <= 16)    {
        while (key.size() < 16) {
            key.push_back(Byte(0));
        }
    }
    else if  (key.size() <= 24)    {
        while (key.size() < 24) {
            key.push_back(Byte(0));
        }
    }
    else if  (key.size() <= 32)    {
        while (key.size() < 32) {
            key.push_back(Byte(0));
        }
    }
    else {
        key.resize(32);
    }
    return key;
};