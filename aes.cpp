#include <cstdio>
#include <cstring>
#include "aes.h"
#include "iostream"

using namespace std;

AES::AES(int keyLen) {
    this->Nb = 4;
    switch (keyLen) {
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

unsigned char *AES::EncryptECB(unsigned char in[], unsigned int inLen, unsigned char key[], unsigned int &outLen) {

    unsigned char *alignIn = PaddingNulls(in);
    unsigned char *out = new unsigned char[16];
    for (unsigned int i = 0; i < 16; i += 16) {
        EncryptBlock(alignIn + i, out + i, key);
    }

    delete[] alignIn;

    return out;
}

unsigned char *AES::DecryptECB(unsigned char in[], unsigned int inLen, unsigned char key[]) {
    unsigned char *out = new unsigned char[inLen];
    for (unsigned int i = 0; i < inLen; i += 16) {
        DecryptBlock(in + i, out + i, key);
    }

    return out;
}

unsigned char *AES::PaddingNulls(unsigned char in[]) {
    unsigned char *alignIn = new unsigned char[16];
    int inLen = (sizeof(in) / sizeof(*in));
    memcpy(alignIn, in, inLen);
    memset(alignIn + inLen, 0x00, 16 - inLen);
    return alignIn;
}

void AES::EncryptBlock(unsigned char in[], unsigned char out[], unsigned char key[]) {
    unsigned char *ExpandedKey = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion(key, ExpandedKey);
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

    AddRoundKey(state, ExpandedKey);

    for (round = 1; round <= Nr - 1; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, ExpandedKey + round * 4 * Nb);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, ExpandedKey + Nr * 4 * Nb);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }

    delete[] state[0];
    delete[] state;
    delete[] ExpandedKey;
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

void AES::SubBytes(unsigned char **state) {
    int i, j;
    unsigned char t;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }

}

void AES::ShiftRow(unsigned char **state, int i, int n) {
    unsigned char t;
    int k, j;
    for (k = 0; k < n; k++) {
        t = state[i][0];
        for (j = 0; j < Nb - 1; j++) {
            state[i][j] = state[i][j + 1];
        }
        state[i][Nb - 1] = t;
    }
}

void AES::ShiftRows(unsigned char **state) {
    ShiftRow(state, 1, 1);
    ShiftRow(state, 2, 2);
    ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b) {
    unsigned char mask = 0x80, m = 0x1b;
    unsigned char high_bit = b & mask;
    b = b << 1;
    if (high_bit) {    // mod m(x)
        b = b ^ m;
    }
    return b;
}

unsigned char AES::mul_bytes(unsigned char a, unsigned char b) {
    unsigned char c = 0, mask = 1, bit, d;
    int i, j;
    for (i = 0; i < 8; i++) {
        bit = b & mask;
        if (bit) {
            d = a;
            for (j = 0; j < i; j++) {    // multiply on x^i
                d = xtime(d);
            }
            c = c ^ d;    // xor to result
        }
        b = b >> 1;
    }
    return c;
}

void AES::MixColumns(unsigned char **state) {
    unsigned char s[4], s1[4];
    int i, j;

    for (j = 0; j < Nb; j++) {
        for (i = 0; i < 4; i++) {
            s[i] = state[i][j];
        }

        s1[0] = muliBytes(0x02, s[0]) ^ muliBytes(0x03, s[1]) ^ s[2] ^ s[3];
        s1[1] = s[0] ^ muliBytes(0x02, s[1]) ^ muliBytes(0x03, s[2]) ^ s[3];
        s1[2] = s[0] ^ s[1] ^ muliBytes(0x02, s[2]) ^ muliBytes(0x03, s[3]);
        s1[3] = muliBytes(0x03, s[0]) ^ s[1] ^ s[2] ^ muliBytes(0x02, s[3]);
        for (i = 0; i < 4; i++) {
            state[i][j] = s1[i];
        }

    }

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

void AES::KeyExpansion(unsigned char key[], unsigned char w[]) {
    unsigned char *temp = new unsigned char[4];
    unsigned char *rcon = new unsigned char[4];

    int i = 0;
    while (i < 4 * Nk) {
        w[i] = key[i];
        i++;
    }

    i = 4 * Nk;
    while (i < 4 * Nb * (Nr + 1)) {
        temp[0] = w[i - 4 + 0];
        temp[1] = w[i - 4 + 1];
        temp[2] = w[i - 4 + 2];
        temp[3] = w[i - 4 + 3];

        if (i / 4 % Nk == 0) {
            RotWord(temp);
            SubWord(temp);
            Rcon(rcon, i / (Nk * 4));
            XorWords(temp, rcon, temp);
        } else if (Nk > 6 && i / 4 % Nk == 4) {
            SubWord(temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }

    delete[]rcon;
    delete[]temp;

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
        s1[0] = mul_bytes(0x0e, s[0]) ^ mul_bytes(0x0b, s[1]) ^ mul_bytes(0x0d, s[2]) ^ mul_bytes(0x09, s[3]);
        s1[1] = mul_bytes(0x09, s[0]) ^ mul_bytes(0x0e, s[1]) ^ mul_bytes(0x0b, s[2]) ^ mul_bytes(0x0d, s[3]);
        s1[2] = mul_bytes(0x0d, s[0]) ^ mul_bytes(0x09, s[1]) ^ mul_bytes(0x0e, s[2]) ^ mul_bytes(0x0b, s[3]);
        s1[3] = mul_bytes(0x0b, s[0]) ^ mul_bytes(0x0d, s[1]) ^ mul_bytes(0x09, s[2]) ^ mul_bytes(0x0e, s[3]);

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
