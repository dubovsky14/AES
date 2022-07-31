#include "../aes/KeyScheduler.h"

#include "../aes/Byte.h"
#include "../aes/SBox.h"

#include <vector>
#include <string>
#include <cstring>

using namespace std;
using namespace AES;

KeyScheduler::KeyScheduler(const std::vector<Byte> &key)  {
    if (key.size() == 16)   {
        m_primary_key = key;
        m_key_size = KeySize::AES128bit;
    }
    else if (key.size() == 24)   {
        m_primary_key = key;
        m_key_size = KeySize::AES192bit;
    }
    else if (key.size() == 32)   {
        m_primary_key = key;
        m_key_size = KeySize::AES256bit;
    }
    else   {
        throw std::string("Invalid key length!");
    }
    InitializeSubkeys();
};

KeyScheduler::KeyScheduler(uint64_t first_half, uint64_t second_half) {
    m_primary_key = get_vector_of_bytes(first_half, second_half);
    InitializeSubkeys();
};

const Byte *KeyScheduler::GetSubKey(unsigned int interation_index)    const {
    return m_subkeys[interation_index];
};

void KeyScheduler::InitializeSubkeys()   {
    const unsigned int n_subkeys   = get_n_subkeys(m_key_size);
    const unsigned int n_key_words = get_n_key_words(m_key_size);
    const unsigned int n_key_schedule_iterations = get_n_key_schedule_iterations(m_key_size);

    Byte    iterations_results[(n_key_schedule_iterations+1)*n_key_words*4];

    memcpy(iterations_results, &m_primary_key[0], m_primary_key.size());

    for (unsigned int i_iter = 1; i_iter <= n_key_schedule_iterations; i_iter++)   {
        const unsigned int subresult_start_pos = i_iter*n_key_words*4;
        memcpy(&iterations_results[subresult_start_pos], &iterations_results[subresult_start_pos - m_primary_key.size()], m_primary_key.size());
        vector<Byte> g_function_result = GFunction(&iterations_results[subresult_start_pos - 4], GetRCKey(i_iter));

        // first word
        for (unsigned int i_byte = 0; i_byte<4; i_byte++)   {
            iterations_results[subresult_start_pos + i_byte] += g_function_result[i_byte];
        }

        for (unsigned int i_word = 1; i_word<n_key_words; i_word++)   {
            for (unsigned int i_byte = 0; i_byte<4; i_byte++)   {
                iterations_results[subresult_start_pos + i_word*4 + i_byte] += iterations_results[subresult_start_pos + (i_word-1)*4 + i_byte];
            }
        }
    }

    for (unsigned int i_sub_key = 0; i_sub_key < n_subkeys; i_sub_key++)   {
        memcpy(&m_subkeys[i_sub_key][0], &iterations_results[i_sub_key*16], 16);
    }
};

std::vector<Byte>   KeyScheduler::AddWords(const Byte *target1, const Byte *target2, unsigned int n_bytes)    {
    vector<Byte>    result;
    result.resize(n_bytes);
    for (unsigned int i_byte = 0; i_byte < n_bytes; i_byte++)   {
        result[i_byte] = target1[i_byte] + target2[i_byte];
    }
    return result;
};

vector<Byte> KeyScheduler::RotateWordLeft(const Byte *word, unsigned int word_size, unsigned int shift_size)    {
    vector<Byte> result;
    result.resize(word_size);
    for (unsigned int i_byte = 0; i_byte < word_size; i_byte++) {
        result[i_byte] = word[(i_byte + shift_size) % word_size];
    }
    return result;
};

vector<Byte> KeyScheduler::GFunction(const Byte *word, const Byte &rc_key)   {
    vector<Byte> result = RotateWordLeft(word, 4, 1);
    for (Byte &byte : result)   {
        byte = SBox::Encrypt(byte);
    }

    result[0] += rc_key;
    return result;
};

Byte    KeyScheduler::GetRCKey(unsigned int index)   {
    unsigned short temp = 1;
    for (unsigned int i = 1; i < index; i++)    temp *= 2;
    temp = Byte::get_modulo_polynomial(temp, Byte::s_modulo_polynomial);
    return Byte((unsigned char)(temp));
};

unsigned int KeyScheduler::get_n_subkeys(KeySize key_size)    {
    if (key_size == KeySize::AES128bit)   return 11;
    if (key_size == KeySize::AES192bit)   return 13;
    if (key_size == KeySize::AES256bit)   return 15;
    throw std::string("Key size not implemented!");
};

unsigned int KeyScheduler::get_n_key_words(KeySize key_size)  {
    if (key_size == KeySize::AES128bit)   return 4;
    if (key_size == KeySize::AES192bit)   return 6;
    if (key_size == KeySize::AES256bit)   return 8;
    throw std::string("Key size not implemented!");
};


unsigned int KeyScheduler::get_n_key_schedule_iterations(KeySize key_size)    {
    if (key_size == KeySize::AES128bit)   return 10;
    if (key_size == KeySize::AES192bit)   return 8;
    if (key_size == KeySize::AES256bit)   return 7;
    throw std::string("Key size not implemented!");

};