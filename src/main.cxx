#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/EncryptIteration.h"
#include "../aes/HelperFunctions.h"
#include "../aes/KeyScheduler128.h"
#include "../aes/AESHandler.h"

#include <iostream>
#include <string>

using namespace std;
using namespace AES;

int main(int argc, const char **argv)   {
    Byte::Initialize();


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

    return 1;

}