#pragma once

#include "Byte.h"
#include "AESHandler.h"


#include<vector>
#include<memory>

namespace AES   {
    class FileEncryptor {
        public:
            FileEncryptor(const std::vector<Byte> &key);

            void SetInitialVector(const std::vector<Byte> &iv);

            void SetInitialVector(uint64_t iv1, u_int64_t iv2);

            void EncryptFile(const std::string &input_file_address, const std::string &output_file_address);

            void DecryptFile(const std::string &input_file_address, const std::string &output_file_address);

        private:
            std::vector<Byte> m_initial_vector = {      Byte(0),Byte(0),Byte(0),Byte(0),
                                                        Byte(0),Byte(0),Byte(0),Byte(0),
                                                        Byte(0),Byte(0),Byte(0),Byte(0),
                                                        Byte(0),Byte(0),Byte(0),Byte(0)};

            std::shared_ptr<AESHandler> m_aes_handler = nullptr;

            Byte    m_temp_input[16];   // array to store teporary input for encryption/decryption
            Byte    m_temp_result[16];  // array to store temporary result of encryption/decryption of one 128-bit block

            void    Encrypt(const unsigned char *data, const Byte *vector_to_add);

            void    Decrypt(const unsigned char *data, const Byte *vector_to_add);

            static void PrintOutBuffer(const unsigned char *buffer);

            static uint64_t get_file_size(const std::string &file_address);

            template<class X1, class X2, class Result>
            static void add_two_128bit_chunks(const X1 *x1, const X2 *x2, Result *result)  {
                *(reinterpret_cast<uint64_t *>(&result[0])) = *(reinterpret_cast<const uint64_t *>(&x1[0])) ^ *(reinterpret_cast<const uint64_t *>(&x2[0]));
                *(reinterpret_cast<uint64_t *>(&result[8])) = *(reinterpret_cast<const uint64_t *>(&x1[8])) ^ *(reinterpret_cast<const uint64_t *>(&x2[8]));
            };

    };
}
