#include <iostream>
#include <fstream>
#include "aes.h"

using namespace std;


int main() {
    cout << "Сайн байна уу AES алгоритмд тавтай морил \n";
    string text;
    ifstream myfile;
    myfile.open("../text.txt");
    while (getline(myfile, text)) {
        int keyLength = 256;
        unsigned char *key;
        unsigned char key128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                                  0x0e, 0x0f};
        unsigned char key192[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                                  0x0e, 0x0f,
                                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
        unsigned char key256[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                                  0x0e, 0x0f,
                                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                                  0x1e, 0x1f};
        int keySize;
        myfile >> keySize;
        switch (keySize) {
            case 128:
                keyLength = 128;
                key = key128;
                break;
            case 192:
                keyLength = 192;
                key = key192;
                break;
            case 256:
                keyLength = 256;
                key = key256;
                break;
        }
        AES aes(keyLength);
        /// Текстийг бэлдэж байна.
        unsigned char plaintextFirst[text.length()];
        copy(text.begin(), text.end(), plaintextFirst);
        unsigned char plainTextEdited[text.length()];
        copy(text.begin(), text.end(), plainTextEdited);
        srand(time(NULL));
        int randomPlainTextIndex = rand() % text.length();
        unsigned char temp = plainTextEdited[randomPlainTextIndex]+1;
        srand(time(NULL));
        int randomCipherKeyIndex = rand() % keyLength;
        unsigned char tempKey = key[randomCipherKeyIndex]+1;
        plainTextEdited[randomPlainTextIndex] = temp;
        int inputSize = sizeof(plaintextFirst);
        int outSize = ((inputSize - 1) / 16 + 1) * 16;


        /// Өгөгдөл өөрчлөгдөөгүй үед
        unsigned char *cipherText = aes.EncryptECB(plaintextFirst, key, inputSize);
        unsigned char *decryptedText = aes.DecryptECB(cipherText, key, outSize);
        aes.printHexArray(plaintextFirst, inputSize, "Plain text");
        aes.printBinaryArray(plaintextFirst, inputSize, "Plain text");
        aes.printHexArray(cipherText, outSize, "Encrypted text");
        aes.printBinaryArray(cipherText, outSize, "Encrypted text");
        cout << "Decrypted text: " << decryptedText << endl;

        /// Өгөгдлийг нэг бит өөрчилсөн өөрчлөлт
        unsigned char *cipherTextEdited = aes.EncryptECB(plainTextEdited, key, inputSize);
        unsigned char *decryptedTextEdited = aes.DecryptECB(cipherTextEdited, key, outSize);
        aes.printHexArray(plainTextEdited, inputSize, "Edited plain text");
        aes.printBinaryArray(plainTextEdited, inputSize, "Edited plain text");
        aes.printHexArray(cipherTextEdited, outSize, "Edited encrypted text");
        aes.printBinaryArray(cipherTextEdited, outSize, "Edited encrypted text");

        cout << "Decrypted text: " << decryptedTextEdited << endl;
        delete[] cipherText;
    }
    myfile.close();
    return 0;
}
