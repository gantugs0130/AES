//
// Created by gantugs on 5/3/20.
//

#ifndef AES_AES_H
#define AES_AES_H

class AES {
private:
    int Nb; // Шифрлэх өгөгдлийн хэнэд үг байхийг заана үг нь 4 байт AES-д Nb = 4 байдаг.
    int Nk; // Шифлэлтэнд ашиглагдах түлхүүрийн хэдэн үг хэмжээтэй байхийг заана. Nk = 4, 6, 8 байдаг.
    int Nr; // Шифрлэлтэнд олон үеээр шифлэдэг бөгөөд түүний хэдэн удаа хийхийг заадаг энэ нь 10 12 14 байдаг.

    /*!
     * Ширлэгдэж буй хүснэгтийн байт бүрийг S_Box хүснэгтийн харгалзах байтаар солих үйлдэл хийнэ.
     * @param state шифрлэгдэж буй өгөгдөл буюу 2 хэмжээст хүснэгт байна.
     */
    void SubBytes(unsigned char **state);

    /*!
     * Өгөгдсөн мөрийг өгөгдсөн тоогоор зүүн цикл шилжүүлэлт хийнэ.
     * @param state шифрлэгдэж буй өгөгдөл буюу 2 хэмжээст хүснэг байна.
     * @param i өггөдлийн мөрийн дугаар
     * @param n тухайн мөрийг хэдэн удаа зүүн цикл хийхийг заана.
     */
    void ShiftRow(unsigned char **state, int i, int n);

    /*!
     * Ширлэгдэж буй хүснэгтийн мөр бүрийг харгалзах тооны дагуу зүүн цикл шилжүүлэлт хийнэ.
     * @param state шифрлэгдэж буй өгөгдөл буюу 2 хэмжээст хүснэг байна.
     */
    void ShiftRows(unsigned char **state);

    /*!
     * Байтийг байтаар үржүүлхэд ашиглагдах бөгөөд өгөгдсөн m(x) = x^8 + x^4 + x^3 + x + 1  олон гишүүнтэд модулчлан x-ээр үржих үйлдэл хийнэ.
     * @param b үржигдэх байт байна.
     * @return өгөгдсөн байтийг x-ээр үржүүлээд гарах байт байна
     */
    unsigned char xtime(unsigned char b);

    /*!
     * байтийг байтаар үржих үйлдэлийг алгоритмд буулгасан хэлбэр энэ нь GF(x^8) талбарын хувьд тодорхойлсон болно.
     * @param firstByte эхний байт
     * @param secondByte дараагийн байт
     * @return хоёр байтийн үржвэр байт байна.
     */
    unsigned char multiplyBytes(unsigned char firstByte, unsigned char secondByte);

    /*!
     * Ширлэгдэж буй хүснэгтийн багана бүрийг c(x) = '03'x^3 + '01'x^2+ '01'x + '02' олон гишүүнтээр үржүүлэх үйлдэлийг GF(x^8) талбарын хувьд тодорхойлсон болно.
     * @param state шифрлэгдэж буй өгөгдөл буюу 2 хэмжээст хүснэг байна.
     */
    void MixColumns(unsigned char **state);

    /*!
     * Шифрлэгдэж буй өгөгдөл дээр тухайн үеийн түлхүүрийг нэмэх үйлдэл хийнэ.
     * @param state шифрлэгдэж буй өгөгдөл буюу 2 хэмжээст хүснэг байна
     * @param roundKey тухайн үеийн түлхүүр.
     */
    void AddRoundKey(unsigned char **state, unsigned char *roundKey);

    /*!
     * Үг хэмжээтэй буюу 4 байтийн хувьд S_Box хүснэгтийг ашиглан харгалзах байтаар солих үйлдэл хийнэ.
     * @param word 4 байт хүснэгт байна.
     */
    void SubWord(unsigned char *word);

    /*!
     * Үг хэмжээтэй буюу 4 байтийн хувьд зүүн цикл шилжүүлэлтийг нэг удаа хийнэ.
     * @param word шилүүлэлт хийх 4 байт хүснэгт
     */
    void RotWord(unsigned char *word);

    /*!
     * Үг хэмжээтэй буюу 4 байт 2 үгийг хооронд нь XOR үйлэдийг хийнэ.
     * @param firstWord XOR хийх энхий дох 4 байт хүснэгт
     * @param secondWord XOR хийх 2 дох үг 4 байт хүснэгт
     * @param resultWord үр дүн 4 байт хүснэгт
     */
    void XorWords(unsigned char *firstWord, unsigned char *secondWord, unsigned char *resultWord);

    /*!
     * Түлхүүр өгөтгөх үед ашиглагдах бөгөөд  GF(x^8) талбарын хувьд тогтмол тоонууд байдаг.
     * @param rcon тухайн тогтмолыг хадгална
     * @param n тухайн тогтмолын хэддэх тогтмолыг авхыг заана.
     */
    void Rcon(unsigned char *rcon, int n);

    /*!
     * Шифрлэлтийг тайлах үед ажиглагдах бөгөөд шифрлэгдсэн хүснэгтийн байт бүрийг Inv_S_Box хүснэгтийн харгалзах байтаар солих үйлдэл хийнэ.
     * @param state шифрлэгдсэн өгөгдөл буюу 2 хэмжээст хүснэгт байна.
     */
    void InvSubBytes(unsigned char **state);

    /*!
     * Шифрлэгдсэн хүснэгтийн багана бүрийг d(x) = '0B'x^3 + '0D'x^2+ '09'x + '0E' олон гишүүнтээр үржүүлэх үйлдэлийг GF(x^8) талбарын хувьд тодорхойлсон болно.
     * d(x) нь c(x) олон гишүүнтийн урвуу буюу с(x)^(-1) байна энэ нь багана холих үйлдэлийн урвуу үйлдэл болж өгдөг.
     * @param state шифрлэгдсэн өгөгдөл буюу 2 хэмжээст хүснэг байна.
     */
    void InvMixColumns(unsigned char **state);

    /*!
     * Ширлэгдсэн хүснэгтийн мөр бүрийг харгалзах тооны дагуу зүүн цикл шилжүүлэлт хийнэ.Энэ нь шифрлэх явцад хийсэн үйлдэлийн эсрэг үйлдэл байна.
     * @param state шифрлэгдсэн өгөгдөл буюу 2 хэмжээст хүснэг байна.
     */
    void InvShiftRows(unsigned char **state);

    /*!
     * Шифрлэгдэх гэж байгаа өгөгдлийг 16 байт урттай болгох зорилготой уг өгөгдөлийг 16 бит болгохдоо хоосон утгаар дүүргэх үйлдэл хийнэ
     * @param in Ширлэгдэх гэж байга өгөгдөл
     * @return 16 байт хэмжээтэй шифрлэхэд бэлэн болсон хүснэгт
     */
    unsigned char *SetNulls(unsigned char input[], int inputSize);

    /*!
     * Анхны өгсөн түлхүүрийн тусламжтай үе бүрт ашиглагдах түлхүүрийг гарган авна.
     * @param chiperKey Анхны түлхүүр.
     * @param ExpandedKey NR+1 түлхүүрийг хадгална энд үе бүрт ашиглагдах түлхүүр байна.
     */
    void KeyExpansion(unsigned char cipherKey[], unsigned char ExpandedKey[]);

    /*!
     * Өгөгдлийг шифрлэх үйл ажиллагааг хийнэ.
     * @param inputText шифрлэгдэх өгөгдөл
     * @param cipherText шифрлэсэн өгөгдөл
     * @param chiperKey дундын түлхүүр
     */
    void EncryptBlock(unsigned char plainText[], unsigned char cipherText[], unsigned char cipherKey[]);


    void DecryptBlock(unsigned char cipherText[], unsigned char plainText[], unsigned char cipherKey[]);

public:

    AES(int keyLen = 256);
    /*!
     *
     * @param inputText
     * @param chiperKey
     * @param inputSize
     * @return
     */
    unsigned char *EncryptECB(unsigned char inputText[], unsigned char cipherKey[], int inputSize);
    /*!
     *
     * @param encryptedText
     * @param chiperKey
     * @param outSize
     * @return
     */
    unsigned char *DecryptECB(unsigned char encryptedText[], unsigned char cipherKey[], int outSize);

    void printHexArray(unsigned char a[], unsigned int n, std::string name);
    void printBinaryArray(unsigned char a[], unsigned int n, std::string name);
};

/*
 * Байтийг байтаар солиход зориулагдсан хүснэгт
 */
const unsigned char sbox[16][16] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/*
 * Байтийг байтаар солих үйлдлийн эсрэг үйлдэлд зориулагдсан хүснэгт
 */
const unsigned char inv_sbox[16][16] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,};

#endif //AES_AES_H
