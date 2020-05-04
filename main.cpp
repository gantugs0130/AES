#include <iostream>
#include <iomanip>
#include "aes.h"

using namespace std;


int main() {
    while(true){
        string text;
        cout << "Сайн байна уу AES алгоритмд тавтай морил ";
        cout << "Шифрлэх текстийг оруулж Enter товчыг дарна уу ";
        getline(cin, text);
        cout << "Шифрлэхдээ ашиглах түлхүүрийн уртыг сонгоно уу 128, 192, 256";
        AES aes(256);

        cout << "Шифрлэх текстийг оруулна уу";
        getline(cin, text);
        unsigned char plaintext[text.length()];
        copy(text.begin(), text.end(), plaintext);
        unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                               0x0f};
        int inputSize = sizeof(plaintext);
        int outSize  = ((inputSize - 1)/16+1)* 16;
        unsigned char *cipherText = aes.EncryptECB(plaintext, key, inputSize);
        unsigned char *plainText = aes.DecryptECB(cipherText, key, outSize);
        aes.printHexArray(plaintext,inputSize);
        aes.printHexArray(cipherText,outSize);
        cout << plainText;

        delete[] cipherText;
        return 0;
    }

}
