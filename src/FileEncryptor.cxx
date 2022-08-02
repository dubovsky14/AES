#include "../aes/FileEncryptor.h"

#include <string>
#include <cstring>

using namespace std;
using namespace AES;

FileEncryptor::FileEncryptor(const std::vector<Byte> &key) {
    m_aes_handler = std::make_shared<AESHandler>(key);
};

void FileEncryptor::SetInitialVector(const std::vector<Byte> &iv)   {
    if (iv.size() != 16)    {
        throw std::string("Invalid size of initial vector: " + std::to_string(iv.size()) + " bytes");
    }
    m_initial_vector = iv;
};

void FileEncryptor::SetInitialVector(uint64_t iv1, u_int64_t iv2)   {
    m_initial_vector = get_vector_of_bytes(iv1, iv2);
};

void    FileEncryptor::Encrypt(const unsigned char *data, const Byte *vector_to_add)    {
    // TODO: 2 copies in memory are created, maybe we can optimize this
    memcpy(m_temp_input, data, 16);

    // Add initial vector
    *(reinterpret_cast<uint64_t *>(&m_temp_input[0])) = *(reinterpret_cast<uint64_t *>(&m_temp_input[0])) ^ *(reinterpret_cast<const uint64_t *>(&vector_to_add[0]));
    *(reinterpret_cast<uint64_t *>(&m_temp_input[8])) = *(reinterpret_cast<uint64_t *>(&m_temp_input[8])) ^ *(reinterpret_cast<const uint64_t *>(&vector_to_add[8]));

    m_aes_handler->Encrypt(m_temp_input, m_temp_result);
};


void    FileEncryptor::Decrypt(const unsigned char *data, const Byte *vector_to_add)    {
    m_aes_handler->Decrypt(reinterpret_cast<const Byte *> (data), m_temp_result);

    // Add initial vector
    *(reinterpret_cast<uint64_t *>(&m_temp_result[0])) = *(reinterpret_cast<uint64_t *>(&m_temp_result[0])) ^ *(reinterpret_cast<const uint64_t *>(&vector_to_add[0]));
    *(reinterpret_cast<uint64_t *>(&m_temp_result[8])) = *(reinterpret_cast<uint64_t *>(&m_temp_result[8])) ^ *(reinterpret_cast<const uint64_t *>(&vector_to_add[8]));

};