#include "../aes/Byte.h"
#include "../aes/SBox.h"

#include <iostream>

using namespace std;
using namespace AES;

int main(int argc, const char **argv)   {
    SBox::InitializeSMatrix();
    Byte::Initialize();

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