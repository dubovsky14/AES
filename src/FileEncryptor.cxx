#include "../aes/FileEncryptor.h"

#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <ctime>

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

void FileEncryptor::SetInitialVector()  {
    uint64_t iv_part1 = std::time(0);
    SetInitialVector(uint64_t(0), iv_part1);
};

void FileEncryptor::EncryptFile(const std::string &input_file_address, const std::string &output_file_address)  {
    const uint64_t file_size = get_file_size(input_file_address);

    ifstream input_file(input_file_address, std::ios::binary | std::ios::in);
    unsigned char input_buffer[16];
    ofstream output_file(output_file_address, std::ios::binary | std::ios::out);

    output_file << file_size;

    // Set initial vector and save it into the encrypted file
    if (m_use_initial_vector)   SetInitialVector();
    for (unsigned int i_iv_byte = 0; i_iv_byte < 16; i_iv_byte++)   {
        output_file  << std::noskipws << (m_initial_vector[i_iv_byte]).GetValue();
    }

    Byte initial_vector[16];
    memcpy(initial_vector, &m_initial_vector[0], 16);
    while(input_file.good())    {
        input_file  >> std::noskipws
                    >> input_buffer[0] >> input_buffer[1] >> input_buffer[2] >> input_buffer[3] >> input_buffer[4] >> input_buffer[5] >> input_buffer[6] >> input_buffer[7]
                    >> input_buffer[8] >> input_buffer[9] >> input_buffer[10] >> input_buffer[11] >> input_buffer[12] >> input_buffer[13] >> input_buffer[14] >> input_buffer[15];
        Encrypt(input_buffer, &initial_vector[0]);
        memcpy(initial_vector, m_temp_result, 16);
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
    uint64_t file_size;
    input_file >> file_size;

    // reading initial vector
    unsigned char iv[16];
    for (unsigned int i_iv_byte = 0; i_iv_byte < 16; i_iv_byte++)   {
        input_file  >> std::noskipws >> iv[i_iv_byte];
    }
    memcpy(&m_initial_vector[0], &iv[0], 16);


    const uint64_t number_of_128bit_chunks = file_size/16;
    const short number_of_bytes_in_last_chunk = file_size - number_of_128bit_chunks*16;
    Byte initial_vector[16];
    memcpy(initial_vector, &m_initial_vector[0], 16);
    for (uint64_t i_128bit_chunk = 0; i_128bit_chunk < number_of_128bit_chunks; i_128bit_chunk++)   {
        input_file  >> std::noskipws
                    >> input_buffer[0] >> input_buffer[1] >> input_buffer[2] >> input_buffer[3] >> input_buffer[4] >> input_buffer[5] >> input_buffer[6] >> input_buffer[7]
                    >> input_buffer[8] >> input_buffer[9] >> input_buffer[10] >> input_buffer[11] >> input_buffer[12] >> input_buffer[13] >> input_buffer[14] >> input_buffer[15];
        Decrypt(input_buffer, &initial_vector[0]);
        memcpy(initial_vector, input_buffer, 16);

        output_file  << std::noskipws
                     << (m_temp_result[0]).GetValue() << (m_temp_result[1]).GetValue() << (m_temp_result[2]).GetValue() << (m_temp_result[3]).GetValue() << (m_temp_result[4]).GetValue() << (m_temp_result[5]).GetValue() << (m_temp_result[6]).GetValue() << (m_temp_result[7]).GetValue()
                     << (m_temp_result[8]).GetValue() << (m_temp_result[9]).GetValue() << (m_temp_result[10]).GetValue() << (m_temp_result[11]).GetValue() << (m_temp_result[12]).GetValue() << (m_temp_result[13]).GetValue() << (m_temp_result[14]).GetValue() << (m_temp_result[15]).GetValue();
    }

    if (number_of_bytes_in_last_chunk)  {
        input_file  >> std::noskipws
                    >> input_buffer[0] >> input_buffer[1] >> input_buffer[2] >> input_buffer[3] >> input_buffer[4] >> input_buffer[5] >> input_buffer[6] >> input_buffer[7]
                    >> input_buffer[8] >> input_buffer[9] >> input_buffer[10] >> input_buffer[11] >> input_buffer[12] >> input_buffer[13] >> input_buffer[14] >> input_buffer[15];
        Decrypt(input_buffer, &m_initial_vector[0]);
        for (short i_byte = 0; i_byte < number_of_bytes_in_last_chunk; i_byte++)  {
            output_file  << std::noskipws << (m_temp_result[i_byte]).GetValue();
        }
    }
    output_file.close();
    input_file.close();

};

void    FileEncryptor::Encrypt(const unsigned char *data, const Byte *vector_to_add)    {
    // TODO: 2 copies in memory are created, maybe we can optimize this
    memcpy(m_temp_input, data, 16);

    // Add initial vector
    add_two_128bit_chunks(m_temp_input, vector_to_add, m_temp_input);

    m_aes_handler->Encrypt(m_temp_input, m_temp_result);
};


void    FileEncryptor::Decrypt(const unsigned char *data, const Byte *vector_to_add)    {
    m_aes_handler->Decrypt(reinterpret_cast<const Byte *> (data), m_temp_result);

    // Add initial vector
    add_two_128bit_chunks(m_temp_result, vector_to_add, m_temp_result);
};


void FileEncryptor::PrintOutBuffer(const unsigned char *buffer) {
    for (unsigned int i = 0; i < 16; i++)   {
        cout << buffer[i];
    }
};

uint64_t FileEncryptor::get_file_size(const std::string &file_address) {
    ifstream file(file_address, ios::binary);
    const auto begin = file.tellg();
    file.seekg (0, ios::end);
    const auto end = file.tellg();
    file.close();
    return (end-begin);
};
