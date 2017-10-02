#include "crypto.h"

#include "enclave_utils.h"

#include "sgx_tcrypto.h"
#include "sgx_trts.h" // sgx_read_rand

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

const sgx_cmac_128bit_key_t hash_key = {0};
#define CTR_LEN 12
const uint32_t ctr_inc_bits = 1;
#define NIST_IV_LEN 12
const uint8_t p_iv[NIST_IV_LEN] = { 0 };

// AES-CTR-128
int enc(const void *key, int key_len, const void *src, int src_len, void *dst) {
    uint8_t p_ctr[CTR_LEN] = { 0 };

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_aes_ctr_encrypt(
        (sgx_aes_gcm_128bit_key_t*)key,
        (uint8_t*)src, src_len,
        p_ctr, ctr_inc_bits,
        (uint8_t*)dst);
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        print("[*] aes enc error: %d\n", ret);
        return 0;
    }
}

// AES-CTR-128
int dec(const void *key, int key_len, const void *src, int src_len, void *dst) {
    uint8_t p_ctr[CTR_LEN] = { 0 };
    
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_aes_ctr_decrypt(
        (sgx_aes_gcm_128bit_key_t*)key,
        (uint8_t*)src, src_len,
        p_ctr, ctr_inc_bits,
        (uint8_t*)dst);
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        print("[*] aes dec error: %d\n", ret);
        return 0;
    }
}

// AES-GCM-128
int auth_enc(const void *key, int key_len, const void *src, int src_len, void *dst, void *out_mac) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_rijndael128GCM_encrypt(
        (sgx_aes_gcm_128bit_key_t*)key,
        (uint8_t*)src, src_len,
        (uint8_t*)dst,
        p_iv, NIST_IV_LEN,
        0, 0, // no additional authentication data
        (sgx_aes_gcm_128bit_tag_t*)out_mac);
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        print("[*] auth_enc error: %d\n", ret);
        return 0;
    }
}

// AES-GCM-128
int veri_dec(const void *key, int key_len, const void *src, int src_len, void *dst, const void *in_mac) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_rijndael128GCM_decrypt(
        (sgx_aes_gcm_128bit_key_t*)key,
        (uint8_t*)src, src_len,
        (uint8_t*)dst,
        p_iv, NIST_IV_LEN,
        0, 0, // no additional authentication data
        (sgx_aes_gcm_128bit_tag_t*)in_mac);
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        //print("[*] veri_dec error: %d\n", ret);
        return 0;
    }
}

int hash(const void *msg, int msg_len, void *value)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_rijndael128_cmac_msg(&hash_key,
                                   (const uint8_t*)msg,
                                   msg_len,
                                   (sgx_cmac_128bit_tag_t*)value);
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        print("[*] hash error: %d\n", ret);
        return 0;
    }
}

int prf(const void *key, const void *src, int src_len, void *dst) {
    uint8_t aes_ctr[CTR_LEN] = { 0 };
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_aes_ctr_encrypt((sgx_aes_ctr_128bit_key_t*)key,
        (const uint8_t*)src,
        src_len,
        aes_ctr,
        1,
        (uint8_t*)dst);
    if (ret == SGX_SUCCESS) {
        return 1;
    }
    else {
        print("[*] prf error: %d %d\n", ret, src_len);
        return 0;
    }
}

void draw_rand(void *r, int len)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_read_rand((uint8_t*)r, len);
}

/* RSA */
static BIGNUM* rsa_n = BN_new();
static BIGNUM* rsa_e = BN_new();
static BIGNUM* rsa_d = BN_new();

static RSA *rsa_key = 0;
static int rsaSize = 0;
static int rsaBlockSize = 0;

void tdp_init()
{
    /*static unsigned char n[] =
        "\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
        "\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
        "\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
        "\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
        "\xF5";

    static unsigned char e[] = "\x11";

    static unsigned char d[] =
        "\x0A\x03\x37\x48\x62\x64\x87\x69\x5F\x5F\x30\xBC\x38\xB9\x8B\x44"
        "\xC2\xCD\x2D\xFF\x43\x40\x98\xCD\x20\xD8\xA1\x38\xD0\x90\xBF\x64"
        "\x79\x7C\x3F\xA7\xA2\xCD\xCB\x3C\xD1\xE0\xBD\xBA\x26\x54\xB4\xF9"
        "\xDF\x8E\x8A\xE5\x9D\x73\x3D\x9F\x33\xB3\x01\x62\x4A\xFD\x1D\x51";*/

    static unsigned char n[] =
        "\x00\xa0\x16\xa4\x01\xcb\x26\x54\x82\x5b\xfe\x9f\xaa\xe6\x04"
        "\x75\xdc\x3a\xb9\x02\xb7\x77\x39\xd6\x9c\x75\x83\xf2\xd2\x5f"
        "\x30\xb0\x93\x26\x94\x91\xe5\x77\x52\xfb\xfa\x6a\x3f\x48\x36"
        "\xf4\xc1\x2d\x54\xcb\x2d\xad\xf0\xe5\x8f\xb3\x7e\x1e\xdf\xc6"
        "\x2f\xa3\xfb\x09\x01\x28\xbd\x4c\xf0\x17\xee\xb2\xbb\xa4\x7b"
        "\x77\x53\x11\xbd\x1b\xc1\x20\xc9\xc3\x05\xd2\x53\xa5\xd1\xff"
        "\x43\x37\xe2\x06\x0f\x52\xc7\x52\xe0\xf1\xc8\xcd\x7a\x90\x79"
        "\x5e\x7a\xe7\x71\xe0\x21\xb3\x20\x11\x3f\xbf\x6c\x43\xc6\x8d"
        "\xd0\x2f\xe6\x2f\x0d\x02\x34\x24\x71";


    static unsigned char e[] = "\x01\x00\x01";

    static unsigned char d[] =
        "\x00\x84\x60\xd4\x74\x0b\x3a\x01\xed\xde\x06\x9a\x9f\xa6\x1f"
        "\x10\x1a\xf1\x90\x25\x97\xf2\x86\x28\x5a\x2e\xae\xd2\xaf\x75"
        "\x39\x7c\xf9\xe1\x90\x3f\x68\xc1\x98\x24\x77\x79\x3e\x25\x08"
        "\x14\xb2\x5d\x3a\xdd\xdc\x43\x16\x8d\xad\x9b\x9e\x72\x07\x57"
        "\x09\xf4\x0e\x54\xed\x8a\x72\x64\x6f\x1b\x88\x34\xe2\xa2\x4c"
        "\xc4\x53\x66\xbb\x55\x49\xee\xee\xa2\x74\xc5\x92\x8c\x3b\x0e"
        "\xb4\xea\x90\x05\xc0\x28\x29\xca\xd7\xcd\xf5\xbb\xaf\xa8\xd4"
        "\xbc\x22\xae\x88\x0c\x23\x1f\xf8\x21\xb3\xab\x66\x47\xcc\xe9"
        "\x11\xff\xed\x47\x5c\x33\xa8\x17\xf1";

    BN_bin2bn(n, sizeof(n) - 1, rsa_n);
    BN_bin2bn(e, sizeof(e) - 1, rsa_e);
    BN_bin2bn(d, sizeof(d) - 1, rsa_d);

    /*rsa_key = RSA_new();

    RSA_set0_key(rsa_key,
                 rsa_n,
                 rsa_e,
                 rsa_d);
    RSA_set0_factors(rsa_key,
        BN_bin2bn(p, sizeof(p) - 1, NULL),
        BN_bin2bn(q, sizeof(q) - 1, NULL));
    RSA_set0_crt_params(rsa_key,
        BN_bin2bn(dmp1, sizeof(dmp1) - 1, NULL),
        BN_bin2bn(dmq1, sizeof(dmq1) - 1, NULL),
        BN_bin2bn(iqmp, sizeof(iqmp) - 1, NULL));

    rsaSize = RSA_size(rsa_key);
    rsaBlockSize = rsaSize - 1;*/
}

int rsa_enc(const void* src, int src_len, void* dst)
{
    if (!rsa_key) {
        return -1;
    }

    int rsaSize = RSA_size(rsa_key);
    int rsaBlockSize = rsaSize - 12;
    int blockCount = 0;

    if (src_len <= 0)
        return -1;
    else if (src_len%rsaBlockSize == 0)
        blockCount = src_len / rsaBlockSize;
    else
        blockCount = src_len / rsaBlockSize + 1;

    unsigned char* pln = (unsigned char*)src;
    unsigned char* enc = (unsigned char*)dst;

    for (int i = 0; i<blockCount; i++)
    {
        int blockSize;

        if (src_len>rsaBlockSize)
            blockSize = rsaBlockSize;
        else
            blockSize = src_len;

        int num = RSA_public_encrypt(blockSize, pln, enc, rsa_key, RSA_PKCS1_PADDING);
        if (num != rsaSize)
        {
            print("[*] RSA encryption failed! --%d\n", num);
        }
        else
        {
            //printf("%d encryption successed! --%d\n",i,blockSize);
        }

        src_len -= rsaBlockSize;
        pln += rsaBlockSize;
        enc += rsaSize;
    }

    return blockCount*rsaSize;
}

int rsa_dec(const void* src, int src_len, void* dst)
{
    if (!rsa_key) {
        return -1;
    }

    int rsaSize = RSA_size(rsa_key);
    int rsaBlockSize = rsaSize - 12;
    int blockCount = 0;

    if (src_len>0 && src_len%rsaSize == 0)
        blockCount = src_len / rsaSize;
    else
        return -1;

    unsigned char* enc = (unsigned char*)src;
    unsigned char* pln = (unsigned char*)dst;

    int plnSize = 0;

    for (int i = 0; i<blockCount; i++)
    {
        int num = RSA_private_decrypt(RSA_size(rsa_key), enc, pln, rsa_key, RSA_PKCS1_PADDING);
        if (num <0)
        {
            print("[*] RSA decryption failed! --%d\n", num);
        }
        else
        {
            //printf("%d decryption successed! --%d\n",i,num);
        }

        enc += rsaSize;
        pln += num;
        plnSize += num;
    }

    return plnSize;
}

void tdp_pub(const void * src, int _src_len, void * dst)
{
    // 2048 bit, actually use the first half...
    static const int src_len = 128;

    if (_src_len != RAND_LEN)
    {
        print("[*] tdp_pub length error!\n");
    }

    BIGNUM *a = BN_new();
    BIGNUM *r = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_bin2bn((unsigned char*)src, src_len, a);
    BN_mod_exp(r, a, rsa_e, rsa_n, ctx);
    int rlt_len = BN_bn2bin(r, (unsigned char*)dst);
    // quick fix
    if (rlt_len < src_len) {
        memmove(dst + (src_len - rlt_len), dst, rlt_len);
        memset(dst, 0x0, src_len - rlt_len);
    }

    BN_free(a);
    BN_free(r);
    BN_CTX_free(ctx);
}

void tdp_pri(const void * src, int _src_len, void * dst)
{
    // 2048 bit, actually use the first half...
    static const int src_len = 128;

    if (_src_len != RAND_LEN)
    {
        print("[*] tdp_pri length error!\n");
    }

    BIGNUM *a = BN_new();
    BIGNUM *r = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_bin2bn((unsigned char*)src, src_len, a);
    BN_mod_exp(r, a, rsa_d, rsa_n, ctx);
    int rlt_len = BN_bn2bin(r, (unsigned char*)dst);
    // quick fix
    if (rlt_len < src_len) {
        memmove(dst + (src_len - rlt_len), dst, rlt_len);
        memset(dst, 0x0, src_len - rlt_len);
    }

    BN_free(a);
    BN_free(r);
    BN_CTX_free(ctx);
}