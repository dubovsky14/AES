#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/EncryptIteration.h"
#include "../aes/HelperFunctions.h"
#include "../aes/KeyScheduler128.h"
#include "../aes/AESHandler.h"

#include <iostream>
#include <string>
#include <chrono>

using namespace std;
using namespace AES;

int main(int argc, const char **argv)   {
    Byte::Initialize();
    SBox::Initialize();





    uint64_t zero = 0;
    uint64_t one = 1;
    vector<Byte> key            = get_vector_of_bytes(one, zero);
    vector<Byte> plain_text     = get_vector_of_bytes(zero, one);

    AESHandler aes_handler(key);
    vector<Byte> cipher_text = plain_text;
    aes_handler.Encrypt(&cipher_text[0]);
    vector<Byte> decrypted_text = cipher_text;
    aes_handler.Decrypt(&decrypted_text[0]);

    cout << "key \t\t= ";
    print_out_byte_vector(key);
    cout << "\nplain text \t= ";
    print_out_byte_vector(plain_text);
    cout << "\ncipher text \t= ";
    print_out_byte_vector(cipher_text);
    cout << "\ndecrypted text \t= ";
    print_out_byte_vector(decrypted_text);
    cout << endl;


    const long long int number_of_blocks = 100000000;
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    for (unsigned long long int i = 0; i < number_of_blocks; i++)  {
        aes_handler.Encrypt(&cipher_text[0]);
    }
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    unsigned int dt = std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
    std::cout << "Time difference = " << std::dec << dt << "[ms]" << std::endl;
    std::cout << "Encryption speed = " << (16.*number_of_blocks/(dt/1000.))/1000000. << " MB/s" <<  endl;

    cout << "\ncipher text \t= ";
    print_out_byte_vector(cipher_text);
    cout << endl;
    return 0;

}