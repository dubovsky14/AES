#include "../aes/Byte.h"
#include "../aes/SBox.h"
#include "../aes/EncryptIteration.h"
#include "../aes/HelperFunctions.h"
#include "../aes/KeyScheduler128.h"

#include <iostream>
#include <string>

using namespace std;
using namespace AES;

int main(int argc, const char **argv)   {
    Byte::Initialize();

    uint64_t zero = 0;
    uint64_t one = 1;
    vector<Byte> key            = get_vector_of_bytes(one, zero);
    vector<Byte> plain_text     = get_vector_of_bytes(zero, zero);
    vector<Byte> cipher_text    = plain_text;


    KeyScheduler128 key_scheduler(key);
    EncryptIteration::AddKey(&cipher_text[0], key_scheduler.GetSubKey(0));
    for (unsigned int i_encryption_iter = 1; i_encryption_iter < 10; i_encryption_iter++)   {
        EncryptIteration::Encrypt(&cipher_text[0], key_scheduler.GetSubKey(i_encryption_iter), true);
    }
    EncryptIteration::Encrypt(&cipher_text[0], key_scheduler.GetSubKey(10), false);


    cout << "key \t\t= ";
    print_out_byte_vector(key);
    cout << "\nplain text \t= ";
    print_out_byte_vector(plain_text);
    cout << "\ncipher text \t= ";
    print_out_byte_vector(cipher_text);
    cout << endl;


    return 1;

    unsigned char this_char = 0;
    while(true) {

        Byte inverse = ((Byte(this_char)).get_inverse())*(Byte(this_char));
        Byte encrypted = SBox::Decrypt(Byte(this_char));
        cout << std::hex << (unsigned short)(encrypted.GetValue());
        //cout << std::hex << (unsigned int)(this_char);
        //cout << std::hex << (unsigned int)(inverse.GetValue());
        cout << " ";

        if (this_char % 16 == 15)   {
            cout << endl;
        }
        this_char++;
        if (this_char == 0)  {
            break;
        }
    }

    Byte a(150), b(206);
    Byte c = a*b;
    cout << (unsigned short int)(c.GetValue()) << endl;
    return 0;
}