#include "../aes/AESHandler.h"

#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/KeyScheduler.h"
#include "../aes/EncryptIteration.h"

#include <vector>
#include <string>

using namespace std;
using namespace AES;

AESHandler::AESHandler(uint64_t key_first_half, uint64_t key_second_half)   {
    vector<Byte> key = get_vector_of_bytes(key_first_half, key_second_half);
    Initialize(key);
};


AESHandler::AESHandler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3)  {
    vector<Byte> key = get_vector_of_bytes(key_part1, key_part2, key_part3);
    Initialize(key);
};

AESHandler::AESHandler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3, uint64_t key_part4)  {
    vector<Byte> key = get_vector_of_bytes(key_part1, key_part2, key_part3, key_part4);
    Initialize(key);
};


AESHandler::AESHandler(const std::vector<Byte> &key)    {
    Initialize(key);
};

AESHandler::AESHandler(const unsigned char *key, unsigned int key_size_bits)    {
    if (key_size_bits != 128 && key_size_bits != 192 && key_size_bits != 256)   {
        throw std::string("AESHandler::Invalid key size: " + std::to_string(key_size_bits) + " bits");
    }
    vector<Byte> key_vector;
    for (unsigned i_byte = 0; i_byte < key_size_bits/8; i_byte++)   {
        key_vector.push_back(Byte(key[i_byte]));
    }
    Initialize(key_vector);
};

void AESHandler::Initialize(const std::vector<Byte> &key)   {
    Byte::Initialize();
    SBox::Initialize();

    if (key.size() == 16)    {      // 128 bit key
        m_number_of_iterations = 10;
        m_key_scheduler = std::make_shared<KeyScheduler>(key);
    }
    else if (key.size() == 24)    { // 192 bit key
        m_number_of_iterations = 12;
        m_key_scheduler = std::make_shared<KeyScheduler>(key);
    }
    else if (key.size() == 32)  {   // 256 bit key
        m_number_of_iterations = 14;
        m_key_scheduler = std::make_shared<KeyScheduler>(key);
    }
    else {
        throw std::string("Key length does not match any of the supported AES alternatives: 128, 192 or 256 bin length.");
    }
}

void AESHandler::Encrypt(Byte *text)  const {
    EncryptIteration::AddKey(text, m_key_scheduler->GetSubKey(0));
    for (unsigned int i_encryption_iter = 1; i_encryption_iter < m_number_of_iterations; i_encryption_iter++)   {
        EncryptIteration::Encrypt(text, m_key_scheduler->GetSubKey(i_encryption_iter), true);
    }
    EncryptIteration::Encrypt(text, m_key_scheduler->GetSubKey(m_number_of_iterations), false);

};

void AESHandler::Encrypt(const Byte *plain_text, Byte *cipher_text) const {
    copy_array(plain_text, cipher_text, 16);
    Encrypt(cipher_text);
};

void AESHandler::Encrypt(unsigned char *text)  const {
    Encrypt(reinterpret_cast<Byte *>(text));
};

void AESHandler::Encrypt(const unsigned char *plain_text, unsigned char *cipher_text) const {
    copy_array(plain_text, cipher_text, 16);
    Encrypt(cipher_text);
};

void AESHandler::Decrypt(Byte *text)  const {
    EncryptIteration::Decrypt(text, m_key_scheduler->GetSubKey(m_number_of_iterations), false);
    for (unsigned int i_encryption_iter = 1; i_encryption_iter < m_number_of_iterations; i_encryption_iter++)   {
        EncryptIteration::Decrypt(text, m_key_scheduler->GetSubKey(m_number_of_iterations-i_encryption_iter), true);
    }
    EncryptIteration::AddKey(text, m_key_scheduler->GetSubKey(0));

};

void AESHandler::Decrypt(const Byte *cipher_text, Byte *plain_text)   const {
    copy_array(cipher_text, plain_text, 16);
    Decrypt(plain_text);
};

void AESHandler::Decrypt(unsigned char *text)  const    {
    Decrypt(reinterpret_cast<Byte *>(text));
};

void AESHandler::Decrypt(const unsigned char *cipher_text, unsigned char *plain_text) const {
    copy_array(cipher_text, plain_text, 16);
    Decrypt(plain_text);
};

std::vector<Byte> AESHandler::GetByteVector(const std::string &input_text)  {
    vector<Byte> result;
    const unsigned int length = input_text.length();
    result.resize(length);

    for (unsigned int i = 0; i < length; i++)   {
        result[i] = Byte((unsigned char)(input_text[i]));
    }
    return result;
};