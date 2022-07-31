#include "../aes/AESHandler.h"

#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/KeyScheduler.h"
#include "../aes/EncryptIteration.h"

#include <vector>

using namespace std;
using namespace AES;

AESHandler::AESHandler(uint64_t key_first_half, uint64_t key_second_half)   {
    m_key_scheduler = new KeyScheduler(key_first_half, key_second_half);
    SBox::Initialize();
    Byte::Initialize();
    m_number_of_iterations = 10;
};


AESHandler::AESHandler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3)  {
    m_key_scheduler = new KeyScheduler(key_part1, key_part2, key_part3);
    SBox::Initialize();
    Byte::Initialize();
    m_number_of_iterations = 12;
};

AESHandler::AESHandler(uint64_t key_part1, uint64_t key_part2, uint64_t key_part3, uint64_t key_part4)  {
    m_key_scheduler = new KeyScheduler(key_part1, key_part2, key_part3, key_part4);
    SBox::Initialize();
    Byte::Initialize();
    m_number_of_iterations = 14;

};


AESHandler::AESHandler(const std::vector<Byte> &key)    {
    SBox::Initialize();
    Byte::Initialize();

    if (key.size() == 16)    {      // 128 bin key
        m_number_of_iterations = 10;
        m_key_scheduler = new KeyScheduler(key);
    }
    else if (key.size() == 24)    { // 192 bit key
        m_number_of_iterations = 12;
        m_key_scheduler = new KeyScheduler(key);
    }
    else if (key.size() == 32)  {   // 256 bit key
        m_number_of_iterations = 14;
        m_key_scheduler = new KeyScheduler(key);
    }
    else {
        throw std::string("Key length does not match any of the supported AES alternatives: 128, 192 or 256 bin length.");
    }
};

AESHandler::~AESHandler()   {
    delete m_key_scheduler;
};

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

std::vector<Byte> AESHandler::GetByteVector(const std::string &input_text)  {
    vector<Byte> result;
    const unsigned int length = input_text.length();
    result.resize(length);

    for (unsigned int i = 0; i < length; i++)   {
        result[i] = Byte((unsigned char)(input_text[i]));
    }
    return result;
};