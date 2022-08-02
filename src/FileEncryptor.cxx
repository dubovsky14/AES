#include "../aes/FileEncryptor.h"

#include <string>
#include <cstring>
#include <fstream>
#include <iostream>

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

void FileEncryptor::EncryptFile(const std::string &input_file_address, const std::string &output_file_address)  {
    ifstream input_file(input_file_address, std::ios::binary | std::ios::in);
    unsigned char input_buffer[16];


    ofstream output_file(output_file_address, std::ios::binary | std::ios::out);

    while(input_file.good())    {
        input_file  >> std::noskipws
                    >> input_buffer[0] >> input_buffer[1] >> input_buffer[2] >> input_buffer[3] >> input_buffer[4] >> input_buffer[5] >> input_buffer[6] >> input_buffer[7]
                    >> input_buffer[8] >> input_buffer[9] >> input_buffer[10] >> input_buffer[11] >> input_buffer[12] >> input_buffer[13] >> input_buffer[14] >> input_buffer[15];
        PrintOutBuffer(input_buffer);
        Encrypt(input_buffer, &m_initial_vector[0]);
        //PrintOutBuffer(reinterpret_cast<const unsigned char*> (m_temp_result));
        output_file  << std::noskipws << (m_temp_result[0]).GetValue() << (m_temp_result[1]).GetValue() << (m_temp_result[2]).GetValue() << (m_temp_result[3]).GetValue() << (m_temp_result[4]).GetValue() << (m_temp_result[5]).GetValue() << (m_temp_result[6]).GetValue() << (m_temp_result[7]).GetValue()
                     << (m_temp_result[8]).GetValue() << (m_temp_result[9]).GetValue() << (m_temp_result[10]).GetValue() << (m_temp_result[11]).GetValue() << (m_temp_result[12]).GetValue() << (m_temp_result[13]).GetValue() << (m_temp_result[14]).GetValue() << (m_temp_result[15]).GetValue();
    }
    output_file.close();
    input_file.close();

};

void FileEncryptor::DecryptFile(const std::string &input_file_address, const std::string &output_file_address)  {
    ifstream input_file(input_file_address, std::ios::binary | std::ios::in);
    unsigned char input_buffer[16];

    ofstream output_file(output_file_address, std::ios::binary | std::ios::out);



    while(input_file.good())    {
        input_file  >> std::noskipws
                    >> input_buffer[0] >> input_buffer[1] >> input_buffer[2] >> input_buffer[3] >> input_buffer[4] >> input_buffer[5] >> input_buffer[6] >> input_buffer[7]
                    >> input_buffer[8] >> input_buffer[9] >> input_buffer[10] >> input_buffer[11] >> input_buffer[12] >> input_buffer[13] >> input_buffer[14] >> input_buffer[15];
        //PrintOutBuffer(input_buffer);
        Decrypt(input_buffer, &m_initial_vector[0]);
        PrintOutBuffer(reinterpret_cast<const unsigned char*> (m_temp_result));


        output_file  << std::noskipws
                     << (m_temp_result[0]).GetValue() << (m_temp_result[1]).GetValue() << (m_temp_result[2]).GetValue() << (m_temp_result[3]).GetValue() << (m_temp_result[4]).GetValue() << (m_temp_result[5]).GetValue() << (m_temp_result[6]).GetValue() << (m_temp_result[7]).GetValue()
                     << (m_temp_result[8]).GetValue() << (m_temp_result[9]).GetValue() << (m_temp_result[10]).GetValue() << (m_temp_result[11]).GetValue() << (m_temp_result[12]).GetValue() << (m_temp_result[13]).GetValue() << (m_temp_result[14]).GetValue() << (m_temp_result[15]).GetValue();
    }
    output_file.close();
    input_file.close();

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


void FileEncryptor::PrintOutBuffer(const unsigned char *buffer) {
    for (unsigned int i = 0; i < 16; i++)   {
        cout << short(buffer[i]) << " ";
    }
    cout << endl;
};