#include <cstdio>
#include <cstring>
#include "aes.h"
#include "iostream"

using namespace std;

AES::AES(int chiperKeyLen) {
    this->Nb = 4;
    switch (chiperKeyLen) {
        case 128:
            this->Nk = 4;
            this->Nr = 10;
            break;
        case 192:
            this->Nk = 6;
            this->Nr = 12;
            break;
        case 256:
            this->Nk = 8;
            this->Nr = 14;
            break;
    }
}

unsigned char *AES::EncryptECB(unsigned char inputText[], unsigned char key[], int inputSize) {
    /// Шифрлэгдсэн текст нь хэдэн байт мэдээлэл байх вэ гэдгийг олж байна. Энд шифр болгоны дараа 16 байт шифр текс гарах тул 16 д хуваагдна.
    int outSize = ((inputSize - 1) / 16 + 1) * 16;
    /// Шифрлэх текстийг мөн тийм хэмжээний байт өгөгдөл гэж үзээд эхлэх үлдсэн байтуудыг хоосоноор дүүргэнэ.
    unsigned char *tempText = SetNulls(inputText, inputSize);
    /// Шифрлэгдсэн текстийг хадгалах хүснэгтийг үүсгэсэн.
    unsigned char *out = new unsigned char[outSize];
    /// Шифрлэлт нь 16 байт байтаар шифлэдэг тул 16 байт бүрээр шифрлэнэ.
    for (unsigned int i = 0; i < outSize; i += 16) {
        EncryptBlock(tempText + i, out + i, key);
    }

    delete[] tempText;
    /// Шифрлэсэн текстийг буцаана.
    return out;
}

unsigned char *AES::SetNulls(unsigned char inputText[], int inputSize) {
    ///Гарах текстийн урт
    int outSize = (inputSize / 16 + 1) * 16;
    ///Гарах текстийн урттай байтуудын хүснэгт үүсгэж байна.
    unsigned char *alignIn = new unsigned char[outSize];
    ///Шифрлэх текстийг хуулж өгнө
    memcpy(alignIn, inputText, inputSize);
    ///Үлдсэн байтуудыг нь хоосон утгаар дүүргэж байна.
    memset(alignIn + inputSize, 0x00, outSize - inputSize);
    ///Үүссэн хүснэгтийг буцааж байна.
    return alignIn;
}

void AES::EncryptBlock(unsigned char plainText[], unsigned char cipherText[], unsigned char key[]) {
    /// Үе бүрт ашиглах түлхүүрийг хадгалах хүснэгт
    unsigned char *ExpandedKey = new unsigned char[4 * Nb * (Nr + 1)];
    /// Анхны түлхүүрээс бусад түлхүүрийг үүсгэн үйлдлийг хийж байна.
    KeyExpansion(key, ExpandedKey);
    /// Шифрлэх текстийг шифрлэлтийн явцад 2 хэмжээст хүснэгтэнд хадгалах хүснэгт цаашид state гэж байвал бүгд шифрлэлтийн явцад байгаа текст гэж ойлгоно.
    unsigned char **state = new unsigned char *[4];
    /// Хүснэгтйиг 4 x Nb хэлбэрийн хүснэгт болгон хаягийн зохицуулалт хийж байна.
    int i, j, round;
    state[0] = new unsigned char[4 * Nb];
    for (i = 0; i < 4; i++) {
        state[i] = state[0] + Nb * i;
    }
    /**
     * Хүснэгтэнд шифрлэх текстийн утгуудыг оноож өгч байна. Энэ нь 4 4 өөр таслан багана болгож байгаа гэж ойлгож болно.
     * Жишээ нь plainText = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16] байсан гэвэл
     * state[0] = [1, 5, 9, 13]
     * state[1] = [2, 6, 10, 14]
     * state[2] = [3, 7, 11, 15]
     * state[3] = [4, 8, 12, 16] байна.
     * */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = plainText[i + 4 * j];
        }
    }
    /// state д хамгийн эхний түлхүүрийг нэмэх үйлдлийг хииж байна.
    AddRoundKey(state, ExpandedKey);

    /**
     * Нийт Nr үеийн турж шифрлэх үйл явц хийгдэх боловч сүүлийн үе нь бусдаасаа өөр байдаг
     * Үе бүрт байтийг байтаар солих, мөр шилжүүлэх, багана холих, тухайн үеийн түлхүүрийг нэмэх үйлдлийг хийнэ.
     */
    for (round = 1; round <= Nr - 1; round++) {
        /// Байтийг байтаар солих үйлдэл
        SubBytes(state);
        /// Мөр шүлжүүлэх үйлдэл
        ShiftRows(state);
        /// Багана холих үйлдэл
        MixColumns(state);
        /// Тухайн үеийн түлхүүрийг нэмэх үйлдэл
        AddRoundKey(state, ExpandedKey + round * 4 * Nb);
    }
    ///Сүүлийн удаа байтийг байтаар солих үйлдэл хийнэ.
    SubBytes(state);
    ///Сүүлийн удаа мөр шилжүүлэх үйлдэл хийнэ.
    ShiftRows(state);
    ///Сүүлийн үеийн түлхүүрийг нэмж өгнө.
    AddRoundKey(state, ExpandedKey + Nr * 4 * Nb);

    /**
     * Шифрлэгдсэн хүснэгтийг шифрлэсэн текс буюу нэг хэмжээс хүснэгт болгож байна
     * Энэ нь дээр хийсэн үйлдэлийн эсэргээр нь хийнэ.
     * */
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            cipherText[i + 4 * j] = state[i][j];
        }
    }
    /// санах ойгоо цэвэрлэж байна.
    delete[] state[0];
    delete[] state;
    delete[] ExpandedKey;
}

void AES::KeyExpansion(unsigned char cipherKey[], unsigned char ExpandedKey[]) {
    /// 4 байт хүснэгтүүд дээр үйлдэл хийх бөгөөд түүнийг түр хадгалах хүснэгт.
    unsigned char *tempWord = new unsigned char[4];
    /// GF(2^8) талбарт ашиглагдах тогтмол утгыг хадгалах хүснэгт.
    unsigned char *rcon = new unsigned char[4];

    /// Өргөтгөсөн түлхүүрийн үүсгэхдээ эхлээд өгөгдсөн түлхүүрийг хуулж оноож өгнө.
    /// Өргөтгөсөн түлхүүрийн 4Nr байт болгон нэг үеийн түлхүүр байна.
    for (int j = 0; j < 4 * Nk; ++j) {
        ExpandedKey[j] = cipherKey[j];
    }
    /// 4Nk аас хойших байтуудыг үүсгэнэ.
    int i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        /// Өргөтгөсөн түлхүүрийн сүүлийн 4 байт дээр үйлдлийг хйиж дараагийн 4 байтыг үүсгэнэ
        /// тус 4 байтыг хүснэгт болгон түр хадгалж авна одоо үүн дээр үйлдэл хийнэ.
        tempWord[0] = ExpandedKey[i - 4 + 0];
        tempWord[1] = ExpandedKey[i - 4 + 1];
        tempWord[2] = ExpandedKey[i - 4 + 2];
        tempWord[3] = ExpandedKey[i - 4 + 3];
        /**
         * Энд Өргөтгөсөн түлхүүрийг үүсгэхдээ үндсэн түлхүүрийг ашиглахын тулд Nk байт байтаар нь дараагын Nk байтыг үүсгэдэг
         * Дараагын Nk байтруу шилжиж байвал Үг эргүүлэх, байтыг байтаар солих, Тогтмол утгаар XOR хийх үйлдэлүүдийг хийнэ.
         * */
        if (i / 4 % Nk == 0) {
            /// Зүүн цикцл шилжүүлэх үйлдлийг түр хадгалсан хүснэгт дээр хийнэ.
            RotWord(tempWord);
            /// Байтийг байтаар солих үйлдлийг уг хүснэгтэн дээр хийнэ.
            SubWord(tempWord);
            /// Тогтмол хүснэгтийг үүсгэнэ.
            Rcon(rcon, i / (Nk * 4));
            /// Тогтмол утгатай XOR үйлдэлийг хийнэ.
            XorWords(tempWord, rcon, tempWord);
        } else if (Nk > 6 && i / 4 % Nk == 4) {
            /// Nk = 8 үед 32 байтаар циклдэх ба түлхүүрийг 16 16 байтаар нь авах бөгөөд тус 32 байт нь эхний 4 байтаас хамаарж үүсэх тул
            /// шифлэлтийн 2 түлхүүр 4 байтаас хамааж болохгүй тул голд нь өөрчиллөлтийг хийж өгнө.
            SubWord(tempWord);
        }
        /**
         * Тухайн цикл эхлээгүй үед өмнөх 4 байтыг авч мөн түүнд харгалзах өмнөх циклийн 4 байтыг авч хооронд нь XOR үйлдэлийг хийж гарган авна.
         * */
        ExpandedKey[i + 0] = ExpandedKey[i - 4 * Nk] ^ tempWord[0];
        ExpandedKey[i + 1] = ExpandedKey[i + 1 - 4 * Nk] ^ tempWord[1];
        ExpandedKey[i + 2] = ExpandedKey[i + 2 - 4 * Nk] ^ tempWord[2];
        ExpandedKey[i + 3] = ExpandedKey[i + 3 - 4 * Nk] ^ tempWord[3];
        /// дараагын 4 байтруу шилжнэ.
        i += 4;
    }
    /// санах ойгоо цэвэрлэж  байна.
    delete[]rcon;
    delete[]tempWord;

}

void AES::SubBytes(unsigned char **state) {
    unsigned char t;
    /**
     * S-Box д харгалзах байтаар нь уг байтыг солино.
     * S-Box нь 16x16 хүснэгт бөгөөд 16 тийн ямарч тэмдэгт байсан түүнд харгалзах байтыг агуулдаг.
     * */
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            t = state[i][j];
            /**
             * Энд a = sbox[t/16][t%16] гэвэл
             * t = inv_sbox[a/16][a%16] байна. Энэ нь хүснэгтийг хувиргахад
             * өмнөх өгөгдлөл байгүй болсон хэдийч буцаан гаргаж болж байгаа учир давуу талийг олгож байна.
             * */
            state[i][j] = sbox[t / 16][t % 16];
        }
    }

}

void AES::ShiftRows(unsigned char **state) {
    /// Мөр бүрт харгалзах зүүн цикл шилжүүлэх тоо байдаг энд харгалзан 0 1 2 3 байна.
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

void AES::ShiftRow(unsigned char **state, int rowNumber, int shiftCount) {
    /// Зүүн цикл шилжүүлхэд тухайн мөрийн эхний байтийг түр хадгалах хувсагч.
    unsigned char tempByte;
    /// Өгсөн тоогоор байтийг зүүн цикл шилжүүлхэд үйлдэл хийнэ.
    for (int count = 0; count < shiftCount; count++) {
        /// Мөрийн эхний байтыг хадгалж авна.
        tempByte = state[rowNumber][0];
        /// Мөрийн багана бүрийг зүүн тийш нэг байт шилжүүлэх үйлдэл.
        for (int col = 0; col < Nb - 1; col++) {
            state[rowNumber][col] = state[rowNumber][col + 1];
        }
        /// Сүүлийн нэг байтд хадгалж байсан утгаа өгнө.
        state[rowNumber][Nb - 1] = tempByte;
    }
}

unsigned char AES::xtime(unsigned char b) {
    /**
     * mask = 10000000 гэсэн битийн задаргаатай байх бөгөөд үүгээр тухайн байтын эхний битийг 1 эсвэл 0 ийг мэдэх боломжтой.
     * mx = x^8 + x^4 + x^3 + x + 1 олон гишүүнтйн 16 тийн бичлгээр дүрслэв.
     * */
    unsigned char mask = 0x80, mx = 0x1b;
    /// хамгийн урд талын битийг олно энэ нь өөр үйлдэл хийх эсхийг шийддэг.
    unsigned char bit = b & mask;
    /// байтыг зүүн тийш нэг бит шилжүүлнэ.
    b = b << 1;
    /// хэрэв хамгийн урд талийн бит нь 1 байвал гарсан үр дүнг m(x) д модулчлах үйлдлийг хийнэ. Энэ нь сүүлийн 8 битийг хооронд нь XOR үйлдэл хийх юм.
    if (bit) {
        b = b ^ mx;
    }
    /// байтийг  m(x) д модулчлан зүүн нэг цикл үйлдэл буюу x ээр үржүүлэх үйлдэлийн үр дүнг буцаана.
    return b;
}

unsigned char AES::multiplyBytes(unsigned char firstByte, unsigned char secondByte) {
    /**
     * Хоёр байтийг үржвэрийг resultByte д хадгална.
     * mask 00000001 бит байх бөгөөд байтийн сүүлийн битийг 0 эсхийг шалгахад ашиглана.
     * байтийн сүүлийн битийг хадгална.
     * tempByte байтуудыг олон гишүүнт гэж үзээд GF(2^8) талбарт үржих үйлдэл хийж байгаа гэж үзээд firstByte(x), secondByte(x)
     * хаалт задлан үржүүлхэд эхний байтыг үржихэд гарсан үр дүнг хадгалах зорилготой.
     * */
    unsigned char resultByte = 0, mask = 1, bit, tempBype;
    /// secondByte ийн сүүлийн битээс эхлэж үржигдэхүүнд задлах үйлдэлийг хийнэ.
    for (int i = 0; i < 8; i++) {
        /// сүүлийн битийг олж байна.
        bit = secondByte & mask;
        /// сүүлийн бит нь 1 байвал тухайн битийн байрлаж байсан буюу анх x^i  зэрэгтэй байсан гэж үзээд i удаа х ээр үржүүлэх үйлдэл хийнэ.
        if (bit) {
            /// эхний байтийг хадгалж авна энд эхний байт нь өөрчлөгдөж болохгүй тул.
            tempBype = firstByte;
            for (int j = 0; j < i; j++) {
                /// эхний байтийг x ээр үржүүлж хадгалж авна.
                tempBype = xtime(tempBype);
            }
            /// үржүүлж дуусаад хариун дээрээ нэмж өгнө.
            resultByte = resultByte ^ tempBype;
        }
        /// secondByte байтийг баруун тийш 1 бит шилжүүлнэ энэ нь урд талын битүүдийг арагш авчирч 0 1 эсхийг нь мэдхэд ашиглагдаж байна.
        secondByte = secondByte >> 1;
    }
    /// үр дүнг буцаана.
    return resultByte;
}

void AES::MixColumns(unsigned char **state) {
    /// Багана холих үйлдэлд
    unsigned char s[4], tempColumn[4];
    for (int j = 0; j < Nb; j++) {
        for (int i = 0; i < 4; i++) {
            s[i] = state[i][j];
        }
        tempColumn[0] = multiplyBytes(0x02, s[0]) ^ multiplyBytes(0x03, s[1]) ^ s[2] ^ s[3];
        tempColumn[1] = s[0] ^ multiplyBytes(0x02, s[1]) ^ multiplyBytes(0x03, s[2]) ^ s[3];
        tempColumn[2] = s[0] ^ s[1] ^ multiplyBytes(0x02, s[2]) ^ multiplyBytes(0x03, s[3]);
        tempColumn[3] = multiplyBytes(0x03, s[0]) ^ s[1] ^ s[2] ^ multiplyBytes(0x02, s[3]);
        for (int i = 0; i < 4; i++) {
            state[i][j] = tempColumn[i];
        }
    }
}

unsigned char *AES::DecryptECB(unsigned char encryptedText[], unsigned char cipherKey[], int outSize) {
    ///Шифрлэлтийг тайлаад хадгалах хүснэгт.
    unsigned char *inputText = new unsigned char[outSize];
    /// Шифр тайлалт нь 16 байт байтаар хийгддэг тул 16 байт бүрээр давтана.
    for (unsigned int i = 0; i < outSize; i += 16) {
        DecryptBlock(encryptedText + i, inputText + i, cipherKey);
    }
    /// Шифрлэлтийг тайлсан текстийг буцаана.
    return inputText;
}

void AES::DecryptBlock(unsigned char in[], unsigned char out[], unsigned char key[]) {
    unsigned char *w = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, w);
    unsigned char **state = new unsigned char *[4];
    state[0] = new unsigned char[4 * Nb];
    int i, j, round;
    for (i = 0; i < 4; i++) {
        state[i] = state[0] + Nb * i;
    }


    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey(state, w + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--) {
        InvSubBytes(state);
        InvShiftRows(state);
        AddRoundKey(state, w + round * 4 * Nb);
        InvMixColumns(state);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, w);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
    delete[] w;
}

void AES::AddRoundKey(unsigned char **state, unsigned char *roundKey) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ roundKey[i + 4 * j];
        }
    }
}

void AES::SubWord(unsigned char *word) {
    int i;
    for (i = 0; i < 4; i++) {
        word[i] = sbox[word[i] / 16][word[i] % 16];
    }
}

void AES::RotWord(unsigned char *word) {
    unsigned char c = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = c;
}

void AES::XorWords(unsigned char *firstWord, unsigned char *secondWord, unsigned char *resultWord) {
    int i;
    for (i = 0; i < 4; i++) {
        resultWord[i] = firstWord[i] ^ secondWord[i];
    }
}

void AES::Rcon(unsigned char *rcon, int n) {
    int i;
    unsigned char c = 1;
    for (i = 0; i < n - 1; i++) {
        c = xtime(c);
    }

    rcon[0] = c;
    rcon[1] = rcon[2] = rcon[3] = 0;
}


void AES::InvSubBytes(unsigned char **state) {
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void AES::InvMixColumns(unsigned char **state) {
    unsigned char s[4], s1[4];
    int i, j;

    for (j = 0; j < Nb; j++) {
        for (i = 0; i < 4; i++) {
            s[i] = state[i][j];
        }
        s1[0] = multiplyBytes(0x0e, s[0]) ^ multiplyBytes(0x0b, s[1]) ^ multiplyBytes(0x0d, s[2]) ^
                multiplyBytes(0x09, s[3]);
        s1[1] = multiplyBytes(0x09, s[0]) ^ multiplyBytes(0x0e, s[1]) ^ multiplyBytes(0x0b, s[2]) ^
                multiplyBytes(0x0d, s[3]);
        s1[2] = multiplyBytes(0x0d, s[0]) ^ multiplyBytes(0x09, s[1]) ^ multiplyBytes(0x0e, s[2]) ^
                multiplyBytes(0x0b, s[3]);
        s1[3] = multiplyBytes(0x0b, s[0]) ^ multiplyBytes(0x0d, s[1]) ^ multiplyBytes(0x09, s[2]) ^
                multiplyBytes(0x0e, s[3]);

        for (i = 0; i < 4; i++) {
            state[i][j] = s1[i];
        }
    }
}

void AES::InvShiftRows(unsigned char **state) {
    ShiftRow(state, 1, Nb - 1);
    ShiftRow(state, 2, Nb - 2);
    ShiftRow(state, 3, Nb - 3);
}

void AES::printHexArray(unsigned char a[], unsigned int n) {
    for (int i = 0; i < n; i++) {
        printf("%02x ", a[i]);
    }
}
