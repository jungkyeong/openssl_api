#include "main.h"
#include "Util.h"
#include "Define.h"
#include "ConfigRead.h"
#include "CipherAPI.h"
#include "../lib/json/json.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string>
#include <cstring>
#include <dlfcn.h> // library load

Util util;
ConfigRead configread;
CipherAPI cipherapi;

int main() {

    // 1. make hash value
    unsigned char hashvalue[32];
    int hash_len = cipherapi.hash_make_value((char*)"dsa", hashvalue, 32, ALG_SHA256);
    for(int i = 0; i < hash_len; i++){
        printf("%02x ", hashvalue[i]);
    }

    unsigned char driv_key[32]={0};
    unsigned char salt[16]={0};
    cipherapi.generate_rand_data(salt, SALT_LEN);
    int status = cipherapi.pbkdf_key_generate("password", salt, SALT_LEN, driv_key, 32);
    if(status ==0){
    printf("Generated Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", driv_key[i]);
    }
    printf("\n");
    }

    unsigned char encrypted[1024];
    unsigned char decrypted[1024];
    int enc_len = cipherapi.enc_sym_data("A1Faf019", driv_key, driv_key, ALG_ARIA256, encrypted, 1024);
    if(enc_len ==-1){
      std::cout << "enc fail" << std::endl;
    }
    else{
      std::cout << "enc success" << std::endl;
      std::cout << "enc len: " << enc_len << std::endl;
      for(int i=0; i<enc_len; i++){
        printf("%02x", encrypted[i]);
      }
      printf("\n");
    }

    int dec_len = cipherapi.dec_sym_data(encrypted, enc_len, driv_key, driv_key, ALG_ARIA256, decrypted, 1024);
    if(dec_len==-1){
      std::cout << "dec fail" << std::endl;
    }
    else{
      std::cout << "dec success" << std::endl;
      std::cout << "dec len: " << dec_len << std::endl;
      for(int i=0; i<dec_len; i++){
        printf("%02x", decrypted[i]);
      }
      printf("\n");
      // make string
      std::string asd = util.hex_to_str(decrypted, dec_len);
      std::cout << asd << std::endl;
    }

    memset(driv_key, 0, 32); // key clear


    // define key
    unsigned char private_key[4096] = {0};
    int private_len =0;
    unsigned char public_key[4096] = {0};
    int public_len =0;

    // make rsa key
    status = cipherapi.generate_rsa_key_pair_der(4096, RSA_E_NUM, private_key, private_len, 4096, public_key, public_len, 4096);
    if(status != SUCCESS){
      std::cout << "RSA Generate FAIL" << std::endl;
    } else {
      std::cout << "RSA Generate SUCCESS" << std::endl;
      printf("Private Key Len %d, PRIVATE KEY: \n", private_len);
      for(int i=0; i <private_len; i++){
        printf(" %02x", private_key[i]);
      }
      printf(" \n");

      printf("Public Key Len %d, Public KEY: \n", public_len);
      for(int i=0; i <public_len; i++){
        printf(" %02x", public_key[i]);
      }
      printf(" \n");
    }

    // RSA Encrypted
    const char* msg = "Hello OpenSSL!";
    unsigned char pair_encrypted[4096] = {0};
    int rsa_enc_len = cipherapi.rsa_encrypt(public_key, public_len, (unsigned char*)msg, strlen(msg), pair_encrypted, 4096);
    printf("RSA ENC DATA LENGTH %d \n", rsa_enc_len);
    if(rsa_enc_len > 0){
      for(int i=0; i < rsa_enc_len; i++){
        printf(" %02x", pair_encrypted[i]);
      }
      printf(" \n");
    }

    // RSA Decrypted
    unsigned char pair_decrypted[4096] = {0};
    int rsa_dec_len = cipherapi.rsa_decrypt(private_key, private_len, pair_encrypted, rsa_enc_len, pair_decrypted, 4096);
    printf("RSA DEC DATA LENGTH %d \n", rsa_enc_len);
    if(rsa_dec_len > 0){
      for(int i=0; i < rsa_dec_len; i++){
        printf(" %02x", pair_decrypted[i]);
      }
      printf(" \n");
    }

    // RSA Sign
    unsigned char pair_signature[4096] = {0};
    int signature_len = cipherapi.rsa_sign(private_key, private_len, hashvalue, hash_len, pair_signature, 4096);
    printf("RSA Signature LENGTH %d \n", signature_len);
    if(signature_len > 0){
      for(int i=0; i < signature_len; i++){
        printf(" %02x", pair_signature[i]);
      }
      printf(" \n");
    }

    // RSA verify
    //cipherapi.hash_make_value((char*)"asd", hashvalue);
    status = cipherapi.rsa_verify(public_key, public_len, hashvalue, hash_len, pair_signature, signature_len);

    return 0;
}