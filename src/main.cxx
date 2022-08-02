#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/EncryptIteration.h"
#include "../aes/HelperFunctions.h"
#include "../aes/KeyScheduler.h"
#include "../aes/AESHandler.h"
#include "../aes/FileEncryptor.h"

#include <iostream>
#include <string>
#include <chrono>

using namespace std;
using namespace AES;

int main(int argc, const char **argv)   {

    try {
        uint64_t zero = 0;
        uint64_t one = 1;
        vector<Byte> key            = get_vector_of_bytes(zero, zero, zero, one);
        FileEncryptor file_encryptor(key);

        std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
        if (string(argv[1]) == "encrypt")   {
            cout << "Running encryption\n";
            file_encryptor.EncryptFile(argv[2], argv[3]);
        }
        else    {
            cout << "Running decryption\n";
            file_encryptor.DecryptFile(argv[2], argv[3]);
        }
        cout << endl;
        std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
        float dt = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()/1000.;
        uint64_t file_size = FileEncryptor::get_file_size(argv[2]);
        std::cout << "Encryption(decryption) time = " << std::dec << dt << " s" << std::endl;
        std::cout << "Encryption speed = " << (file_size/dt)/(1024.*1024.) << " MB/s" <<  endl;


        return 0;

    }
    catch (const std::string &e)    {
        cout << e << endl;
    }
}