/*
 * Sophos Deobfuscation Tool
 * by ValdikSS
 */

#define _UNICODE
#define UNICODE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

#define DATAMAXLEN 1000

#define errorexit(msg) \
    do { puts(msg); exit(EXIT_FAILURE); } while (0)
#define hexdump(what, cmax) \
    do { for (i=0; (int)i<(int)cmax; ++i) { printf("%02x", what[i]); }; puts(""); } while (0)

/* Key derivation function data from Sophos obfuscation tool */
static unsigned char kdfdata[] = {
  0x56, 0x44, 0xB2, 0x62, 0x91, 0x12, 0xC5, 0xFA, 0xCF, 0xD1,
  0x59, 0x23, 0xE8, 0xF0, 0x97, 0x49, 0x3B, 0x73, 0x45, 0x5E,
  0xAE, 0x61, 0x34, 0x54, 0x48, 0x5B, 0xC6, 0x1F, 0x78, 0x5F,
  0x00, 0x08, 0xB3, 0x40, 0xFC, 0x34, 0xE0, 0x5A, 0xD9, 0x8B,
  0x71, 0xAE, 0xD7, 0x0D, 0xAB, 0x3E, 0x97, 0xC9
};

/* from https://gist.github.com/barrysteyn/7308212 */
size_t calcDecodeLength(const char *b64input) {
    size_t len = strlen(b64input);
    size_t padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=')
        padding = 2;
    else if (b64input[len-1] == '=')
        padding = 1;

    return (len*3)/4 - padding;
}

static void Base64Decode(char *b64message,
    unsigned char **buffer, size_t *length)
{
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);

    return;
}

int main(int argc, char *argv[]) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *type;
    const EVP_MD *md;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    unsigned char salt[8];
    int i, datalen, tmplen;
    unsigned char data[DATAMAXLEN];
    unsigned char decrypted[DATAMAXLEN] = {0};
    unsigned char *debase64;
    size_t debase64len;
    int outlen;

    if (argc != 2) {
        puts("Sophos Deobfuscation Tool v1.2 by ValdikSS");
        puts("https://github.com/valdikss/sophos-deobfuscation-tool");
        puts("");
        printf("%s [OBFUSCATED_STRING]\r\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Decoding base64-encoded binary data */
    Base64Decode(argv[1], &debase64, &debase64len);
    if (debase64len <= 12 || debase64len >= (DATAMAXLEN - 32)) {
        errorexit("Error processing string!");
    }

    /* Obfuscated strings begin with 0x07 0x08 */
    if (debase64[0] != 0x07 || debase64[1] != 0x08) {
        errorexit("Unknown string format!");
    }

    /* Copying salt from supplied obfuscated string */
    memcpy(salt, debase64 + 2, 8);
    datalen = debase64len - 10;
    memcpy(data, debase64 + 10, datalen);

    printf("Encrypted data size = %ld\r\n", debase64len);

    type = EVP_des_ede3_cbc();
    md = EVP_md5();

    /* Restoring key and IV from salt inside the file and kdfdata
     * from the program
     */
    EVP_BytesToKey(type, md, salt, kdfdata, sizeof(kdfdata), 1, key, iv);

    printf("Data: ");
    hexdump(data, datalen);
    printf("KDF Salt: ");
    hexdump(salt, sizeof(salt));
    printf("Key: ");
    hexdump(key, EVP_CIPHER_key_length(type));
    printf("IV: ");
    hexdump(iv, EVP_CIPHER_iv_length(type));
    puts("");

    /* Decrypting data */
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(ctx, type, key, iv);
    EVP_DecryptUpdate(ctx, decrypted, &outlen, data, datalen);
    EVP_DecryptFinal(ctx, decrypted + outlen, &tmplen);
    EVP_CIPHER_CTX_free(ctx);

    printf("Deobfuscated HEX: ");
    hexdump(decrypted, outlen + tmplen);
    printf("Deobfuscated string: ");
    puts((char*)decrypted);
    /*printf("Deobfuscated wide string 1: %ls", (wchar_t*)decrypted);
    puts("");*/
    printf("Deobfuscated wide string: ");
    fwrite(decrypted, outlen + tmplen, 1, stdout);
    puts("");

    exit(EXIT_SUCCESS);
}
