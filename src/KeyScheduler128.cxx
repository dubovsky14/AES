#include "../aes/KeyScheduler128.h"

#include "../aes/Byte.h"
#include "../aes/SBox.h"

#include <vector>
#include <string>

using namespace std;
using namespace AES;

KeyScheduler128::KeyScheduler128(const std::vector<Byte> &key)  {
    if (key.size() != 16)   {
        throw std::string("KeyScheduler128: Invalid key length!");
    }
    m_primary_key = key;
    InitializeSubkeys();
};

KeyScheduler128::KeyScheduler128(uint64_t first_half, uint64_t second_half) {
    m_primary_key = get_vector_of_bytes(first_half, second_half);
    InitializeSubkeys();
};

const Byte *KeyScheduler128::GetSubKey(unsigned int interation_index)    const {
    return m_subkeys[interation_index];
};

void KeyScheduler128::InitializeSubkeys()   {
    vector<vector<Byte> > temp_subkeys;
    temp_subkeys.resize(11);
    temp_subkeys[0] = m_primary_key;
    for (unsigned int i_iter = 1; i_iter < 11; i_iter++)   {
        temp_subkeys[i_iter] = temp_subkeys[i_iter-1];
        vector<Byte> g_function_result = GFunction(&temp_subkeys[i_iter][12], GetRCKey(i_iter));

        // first word
        for (unsigned int i_byte = 0; i_byte<4; i_byte++)  temp_subkeys[i_iter][i_byte] += g_function_result[i_byte];

        for (unsigned int i_word = 1; i_word<4; i_word++)   {
            for (unsigned int i_byte = 0; i_byte<4; i_byte++)   {
                temp_subkeys[i_iter][i_word*4+i_byte] += temp_subkeys[i_iter][(i_word-1)*4+i_byte];
            }
        }
    }


    for (unsigned int i_iter = 0; i_iter < 11; i_iter++)   {
        for (unsigned int i_byte = 0; i_byte<16; i_byte++)   {
            m_subkeys[i_iter][i_byte] = temp_subkeys[i_iter][i_byte];
        }
    }
};

std::vector<Byte>   KeyScheduler128::AddWords(const Byte *target1, const Byte *target2, unsigned int n_bytes)    {
    vector<Byte>    result;
    result.resize(n_bytes);
    for (unsigned int i_byte = 0; i_byte < n_bytes; i_byte++)   {
        result[i_byte] = target1[i_byte] + target2[i_byte];
    }
    return result;
};

vector<Byte> KeyScheduler128::RotateWordLeft(const Byte *word, unsigned int word_size, unsigned int shift_size)    {
    vector<Byte> result;
    result.resize(word_size);
    for (unsigned int i_byte = 0; i_byte < word_size; i_byte++) {
        result[i_byte] = word[(i_byte + shift_size) % word_size];
    }
    return result;
};

vector<Byte> KeyScheduler128::GFunction(const Byte *word, const Byte &rc_key)   {
    vector<Byte> result = RotateWordLeft(word, 4, 1);
    for (Byte &byte : result)   {
        byte = SBox::Encrypt(byte);
    }

    result[0] += rc_key;
    return result;
};

Byte    KeyScheduler128::GetRCKey(unsigned int index)   {
    unsigned short temp = 1;
    for (unsigned int i = 1; i < index; i++)    temp *= 2;
    temp = Byte::get_modulo_polynomial(temp, Byte::s_modulo_polynomial);
    return Byte((unsigned char)(temp));
};