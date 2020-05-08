#include <iostream>
#include <fstream>
#include <cstring>
#include "aes.h"

/// Түлхүүрийг үүсгэв
unsigned char key128[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                          0x0e, 0x0f};
unsigned char key192[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                          0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
unsigned char key256[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                          0x0e, 0x0f,
                          0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                          0x1e, 0x1f};
using namespace std;


void someChanges() {
    cout << "Сайн байна уу AES алгоритмд тавтай морил \n";
    string text;
    ifstream myfile;
    myfile.open("../text.txt");
    while (getline(myfile, text)) {
        int keyLength = 256;
        unsigned char *key;


        string keySizeString;
        myfile >> keySizeString;
        int keySize = std::stoi(keySizeString);
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
        cout << keyLength << " бит түлхүүртэй үед шифрлэлт нь" << endl;
        AES aes(keyLength);
        /// Текстийг бэлдэж байна.
        unsigned char plaintextFirst[text.length()];
        copy(text.begin(), text.end(), plaintextFirst);

        int inputSize = sizeof(plaintextFirst);
        int outSize = ((inputSize - 1) / 16 + 1) * 16;


        /// Өгөгдөл өөрчлөгдөөгүй үед
        unsigned char *cipherText = aes.EncryptECB(plaintextFirst, key, inputSize);
        unsigned char *decryptedText = aes.DecryptECB(cipherText, key, outSize);
        aes.printHexArray(plaintextFirst, inputSize, "Plaintext");
        aes.printBinaryArray(plaintextFirst, inputSize, "Plaintext");
        aes.printHexArray(cipherText, outSize, "Encrypted text");
        aes.printBinaryArray(cipherText, outSize, "Encrypted text");
        cout << "Decrypted text: " << decryptedText << endl;

        /// Өгөгдлийг нэг бит өөрчлөгдхөд
        unsigned char plainTextEdited[text.length()];
        copy(text.begin(), text.end(), plainTextEdited);
        srand(time(NULL));
        int randomPlainTextIndex = rand() % text.length();
        unsigned char temp = plainTextEdited[randomPlainTextIndex] + 1;
        plainTextEdited[randomPlainTextIndex] = temp;
        unsigned char *cipherTextEdited = aes.EncryptECB(plainTextEdited, key, inputSize);
        unsigned char *decryptedTextEdited = aes.DecryptECB(cipherTextEdited, key, outSize);
        aes.printHexArray(plainTextEdited, inputSize, "Edited plain text");
        aes.printBinaryArray(plainTextEdited, inputSize, "Edited plain text");
        aes.printHexArray(cipherTextEdited, outSize, "Plaintext edited encrypted text");
        aes.printBinaryArray(cipherTextEdited, outSize, "Plaintext edited Encrypted text");
        cout << "Decrypted text: " << decryptedTextEdited << endl;

        /// Түлхүүрийн утга нэг бит өөрчлөгдхөд
        unsigned char *keytEdited = new unsigned char[keyLength];
        memcpy(keytEdited, key, keyLength);
        srand(time(NULL));
        int randomCipherKeyIndex = rand() % keyLength;
        unsigned char tempKey = key[randomCipherKeyIndex] + 1;
        keytEdited[randomPlainTextIndex] = tempKey;
        unsigned char *cipherTextEditedByCipher = aes.EncryptECB(plaintextFirst, key, inputSize);
        unsigned char *decryptedTextEditedByCipher = aes.DecryptECB(cipherTextEditedByCipher, key, outSize);
        aes.printHexArray(plaintextFirst, inputSize, "Plain text");
        aes.printBinaryArray(plaintextFirst, inputSize, "Plain text");
        aes.printHexArray(cipherTextEditedByCipher, outSize, "Cipher edited encrypted text");
        aes.printBinaryArray(cipherTextEditedByCipher, outSize, "Cipher edited  encrypted text");
        cout << "Decrypted text: " << decryptedTextEditedByCipher << endl;
        string t;
        getline(myfile, t);
    }
    myfile.close();
}

void analysis() {
    string text;

    double time128 = 0;
    double time192 = 0;
    double time256 = 0;
    int byte128 = 0;
    int byte192 = 0;
    int byte256 = 0;
    int count128 = 0;
    int count192 = 0;
    int count256 = 0;

    ifstream myfile;
    myfile.open("../test.txt");
    while (getline(myfile, text)) {
        if (text.length() > 0) {
            int keyLength = 128;
            AES aes(keyLength);
            /// Текстийг бэлдэж байна.
            unsigned char plaintextFirst[text.length()];
            int inputSize = sizeof(plaintextFirst);
            clock_t start = clock();
            aes.EncryptECB(plaintextFirst, key128, inputSize);
            double duration = (clock() - start) / (double) CLOCKS_PER_SEC;
            time128 += duration;
            byte128 += inputSize;
            count128++;
        }
    }
    myfile.close();
    myfile.open("../test.txt");
    while (getline(myfile, text)) {
        if (text.length() > 0) {
            int keyLength = 192;
            AES aes(keyLength);
            /// Текстийг бэлдэж байна.
            unsigned char plaintextFirst[text.length()];
            int inputSize = sizeof(plaintextFirst);
            clock_t start = clock();
            aes.EncryptECB(plaintextFirst, key192, inputSize);
            double duration = (clock() - start) / (double) CLOCKS_PER_SEC;
            time192 += duration;
            byte192 += inputSize;
            count192++;
        }
    }
    myfile.close();
    myfile.open("../test.txt");
    while (getline(myfile, text)) {
        if (text.length() > 0) {
            int keyLength = 256;
            AES aes(keyLength);
            /// Текстийг бэлдэж байна.
            unsigned char plaintextFirst[text.length()];
            int inputSize = sizeof(plaintextFirst);
            clock_t start = clock();
            aes.EncryptECB(plaintextFirst, key256, inputSize);
            double duration = (clock() - start) / (double) CLOCKS_PER_SEC;
            time256 += duration;
            byte256 += inputSize;
            count256++;
        }
    }
    myfile.close();
    ofstream out;
    out.open("../log.txt", ios_base::app);
    out << " 128 time millsecond = " << time128 * 1000 << "; total count = " << count128 << "; total byte = " << byte128
        << "; avarage time  = " << time128 * 1000 / count128 << "; avarage byte = " << byte128 / count128 << endl;
    out << " 192 time millsecond = " << time192 * 1000 << "; total count = " << count192 << "; total byte = " << byte192
        << "; avarage time = " << time192 * 1000 / count192 << "; avarage byte = " << byte192 / count192 << endl;
    out << " 256 time millsecond = " << time256 * 1000 << "; total count = " << count256 << "; total byte = " << byte256
        << "; avarage time = " << time256 * 1000 / count256 << "; avarage byte = " << byte256 / count256 << endl
        << endl;
    cout << time256 * 1000 / count256 / (time128 * 1000 / count128);
    out.close();
}

int main() {
    //  someChanges();
    analysis();
    return 0;
}
