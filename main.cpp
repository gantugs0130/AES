#include <iostream>
#include <iomanip>
#include "aes.h"

using namespace std;


int main() {
    AES aes(128);
    unsigned char plaintext[] = {
            "Gantugsasdfasdfasdfasdfasfsafsafdsqwerrrrrrrrrrrrrrrrrrrrrrrrrrrrrr asdfasdf asdf sadf asdfa sdfas dfasdf sadf sdaf asdf asdf asfda sdfas dfrrrrrrrrrrrrrafdfasdfasfdsadfsadfasdfasdfrrrra"};
    unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                           0x0f};
    int inputSize = sizeof(plaintext);
    unsigned char *out = aes.EncryptECB(plaintext, key, inputSize);
    unsigned char *outt = aes.DecryptECB(out, key, ((inputSize - 1) / 16 + 1) * 16);

    cout << outt;

    delete[] out;
    return 0;
}
