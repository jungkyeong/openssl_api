/**
  ******************************************************************************
  * @file           : Cipher API
  * @brief          : Class Cipher API define use OpenSSL function 
  ******************************************************************************
  * Made in GreenOasis  
  * https://github.com/jungkyeong
  * CopyRigth MIT License
  ******************************************************************************
  * Release History
  * branch name, working description, time
  * version_003: define add version  2025-03-16
  ******************************************************************************
  */

  #ifndef __CIPHER_HPP
  #define __CIPHER_HPP
  
  #include <iostream>
  #include <string>
  #include <cstring>
  #include <openssl/evp.h>
  #include <openssl/err.h>
  #include <openssl/rand.h>

  #define SALT_LEN 16
  #define PBKDF2_ITER 1000
  
  class CipherAPI {

  private:
  
  public:
    /**
    * @brief make hash value SHA-256
    * @param data plain data
    * @param hashed output hash data
    * @return Success: hash length fail: 0
    */
    int hash_make_value(char* data, unsigned char* hashed);

    /**
    * @brief Symmetry encryption data
    * @param data input plain data
    * @param key key data
    * @param iv inital vector
    * @param enc_buf output buffer
    * @param max_buf_size output buffer max size
    * @return Success: enc_buf len, fail -1
    */
    int enc_sym_data(const char* data, unsigned char* key, unsigned char* iv, unsigned char* enc_buf, int max_buf_size);

    /**
    * @brief Symmetry decryption data
    * @param enc_buf input plain data
    * @param enc_buf_len key data
    * @param key key length
    * @param iv inital vector
    * @param dec_buf output buffer
    * @param max_buf_size output buffer max size
    * @return Success: dec_buf len, fail -1
    */
    int dec_sym_data(unsigned char* enc_buf, int enc_buf_len, unsigned char* key, unsigned char* iv, unsigned char* dec_buf, int max_buf_size);

    /**
    * @brief Generate PBKDF2 Key
    * @param password drive key password
    * @param key output key buffer
    * @param key_len key length
    * @return Success: 0 len, fail -1
    */ 
    int pbkdf_key_generate(const char* password, unsigned char* key, int key_len);
  
  };

  #endif /* __CIPHER_HPP */