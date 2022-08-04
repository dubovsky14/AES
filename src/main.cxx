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
        if (argc != 4)   {
            throw std::string("Exactly 3 input arguments are required:\n  1st = action (encrypt or decrypt)\n  2nd = input file\n  3rd = output file");
        }

        cout << "Type the key: ";
        std::string key_string;
        cin >> key_string;
        vector<Byte> key            = GetKeyByteVector(key_string);

        FileEncryptor file_encryptor(key);
        string encryption_type = to_string(8*key.size()) + " bit AES";

        std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
        std::string action = to_upper_copy(argv[1]);

        if (action == "ENCRYPT")   {
            cout << "Running " + encryption_type + " encryption\n";
            cout << "Source: " << argv[2] << endl;
            cout << "Target: " << argv[3] << endl;

            file_encryptor.EncryptFile(argv[2], argv[3]);
        }
        else if (action == "DECRYPT")  {
            cout << "Running " + encryption_type + " decryption\n";
            cout << "Source: " << argv[2] << endl;
            cout << "Target: " << argv[3] << endl;
            file_encryptor.DecryptFile(argv[2], argv[3]);
        }
        else {
            throw std::string("Unkown action: " + action);
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
        abort();
    }
}