#include <iostream>
#include <iomanip>
#include "aes.h"

using namespace std;
const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

int main() {
    AES aes(128);
    unsigned char plaintext[] = "Gantugs";

    unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                           0x0f};
    unsigned int len = 0;
    unsigned char *out = aes.EncryptECB(plaintext, (sizeof(plaintext)/sizeof(*plaintext)), key, len);

    unsigned char *outt = aes.DecryptECB(out, BLOCK_BYTES_LENGTH, key);

    cout << outt;

    delete[] out;
    return 0;
}
