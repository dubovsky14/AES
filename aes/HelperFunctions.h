#pragma once

#include "../aes/Byte.h"

#include <vector>
#include <string>

namespace AES   {
    void print_out_byte_vector(const std::vector<Byte> &byte_vector);

    void to_upper(std::string *input_string);

    std::string  to_upper_copy(const std::string &input_string);

    std::vector<Byte>   GetKeyByteVector(const std::string &key_string);
}