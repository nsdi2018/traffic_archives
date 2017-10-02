#ifndef CRYPTO_H
#define CRYPTO_H

int enc(const void *key, int key_len, const void *src, int src_len, void *dst);

int dec(const void *key, int key_len, const void *src, int src_len, void *dst);

int auth_enc(const void *key, int key_len, const void *src, int src_len, void *dst, void *out_mac);

int veri_dec(const void *key, int key_len, const void *src, int src_len, void *dst, const void *in_mac);

int hash(const void *msg, int msg_len, void *value);

int prf(const void *key, const void *src, int src_len, void *dst);

void draw_rand(void *r, int len);

void tdp_init();

void tdp_pub(const void *src, int src_len, void *dst);

void tdp_pri(const void *src, int src_len, void *dst);

#endif