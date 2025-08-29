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
    int hash_len = cipherapi.hash_make_value((char*)"dsa", hashvalue);
    for(int i = 0; i < hash_len; i++){
        printf("%02x ", hashvalue[i]);
    }

    unsigned char driv_key[32]={0,};
    int status = cipherapi.pbkdf_key_generate("password", driv_key, 32);
    if(status ==0){
    printf("Generated Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", driv_key[i]);
    }
    printf("\n");
    }

    unsigned char encrypted[1024];
    unsigned char decrypted[1024];
    int enc_len = cipherapi.enc_sym_data("A1Faf019", driv_key, (unsigned char*)"1234567890123456", encrypted, 1024);
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

    int dec_len = cipherapi.dec_sym_data(encrypted, enc_len, driv_key, (unsigned char*)"1234567890123456", decrypted, 1024);
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

}