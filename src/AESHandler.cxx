#include "../aes/AESHandler.h"

#include "../aes/Byte.h"
#include "../aes/KeyScheduler128.h"
#include "../aes/EncryptIteration.h"

#include <vector>

using namespace std;
using namespace AES;

AESHandler::AESHandler(uint64_t key_first_half, uint64_t key_second_half)   {
    m_key_scheduler = new KeyScheduler128(key_first_half, key_second_half);
    Byte::Initialize();
};

AESHandler::AESHandler(const std::vector<Byte> &key)    {
    m_key_scheduler = new KeyScheduler128(key);
    Byte::Initialize();
};

AESHandler::~AESHandler()   {
    delete m_key_scheduler;
};

void AESHandler::Encrypt(Byte *text)  const {
    EncryptIteration::AddKey(text, m_key_scheduler->GetSubKey(0));
    for (unsigned int i_encryption_iter = 1; i_encryption_iter < 10; i_encryption_iter++)   {
        EncryptIteration::Encrypt(text, m_key_scheduler->GetSubKey(i_encryption_iter), true);
    }
    EncryptIteration::Encrypt(text, m_key_scheduler->GetSubKey(10), false);

};

void AESHandler::Encrypt(const Byte *plain_text, Byte *cipher_text) const {
    copy_array(plain_text, cipher_text, 16);
    Encrypt(cipher_text);
};

void AESHandler::Decrypt(Byte *text)  const {
    EncryptIteration::Decrypt(text, m_key_scheduler->GetSubKey(10), false);
    for (unsigned int i_encryption_iter = 1; i_encryption_iter < 10; i_encryption_iter++)   {
        EncryptIteration::Decrypt(text, m_key_scheduler->GetSubKey(10-i_encryption_iter), true);
    }
    EncryptIteration::AddKey(text, m_key_scheduler->GetSubKey(0));

};

void AESHandler::Decrypt(const Byte *cipher_text, Byte *plain_text)   const {
    copy_array(cipher_text, plain_text, 16);
    Decrypt(plain_text);
};
