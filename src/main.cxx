#include "../aes/Byte.h"

#include <iostream>

using namespace std;
using namespace AES;

int main(int argc, const char **argv)   {
    Byte a(150), b(206);
    Byte c = a*b;
    cout << (unsigned short int)(c.GetValue()) << endl;
    return 0;
}