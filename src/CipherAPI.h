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

  #include <openssl/rsa.h>
  #include <openssl/pem.h>
  #include <openssl/err.h>
  #include <openssl/sha.h>

  #define SALT_LEN 16
  #define PBKDF2_ITER 1000

  // Debug print
  #ifdef DEBUG
  #define DBG_PRINT(fmt, ...) printf("[DEBUG] " fmt, ##__VA_ARGS__)
  #else
  #define DBG_PRINT(fmt, ...)
  #endif  
  
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


    /**
    * @brief Generate RSA Key
    * @param key_size key size
    * @param e_number RSA e module
    * @return Success: 0 len, fail -1
    */
    RSA* generate_rsa_key_pair(int key_size, unsigned int e_number);

    /**
    * @brief Generate RSA Key
    * @param key_size key size
    * @param e_number RSA e module
    * @param out_priv out private key
    * @param out_priv_len out private key length
    * @param max_priv_buf private key max buffer
    * @param out_pub out public key
    * @param out_pub_len out public key length
    * @param max_pub_buf public key max buffer
    * @return Success: 0, fail -1
    */
    int generate_rsa_key_pair_der(int key_size, unsigned int e_number, unsigned char* out_priv, int& out_priv_len, int max_priv_buf,
                                    unsigned char* out_pub, int& out_pub_len, int max_pub_buf);

    /**
    * @brief RSA Encryption Data from Public key(RSA_PKCS1_PADDING)
    * @param pub_key public key data
    * @param pub_key_len public key length
    * @param plain_data plain data
    * @param plain_data_len plain text length
    * @param enc_data encryption data
    * @param max_enc_buf_len public key max buffer
    * @return Success: output encryption data length, fail -1
    */
    int rsa_encrypt(const unsigned char* pub_key, int pub_key_len, const unsigned char* plain_data, int plain_data_len,
                            unsigned char* enc_data, int max_enc_buf_len);

    /**
    * @brief RSA Decryption Data from Private key(RSA_PKCS1_PADDING)
    * @param priv_key public key data
    * @param priv_key_len public key length
    * @param enc_data plain data
    * @param enc_data_len plain text length
    * @param plain_data encryption data
    * @param max_plain_buf_len public key max buffer
    * @return Success: output encryption data length, fail -1
    */
    int rsa_decrypt(const unsigned char* priv_key, int priv_key_len, const unsigned char* enc_data, int enc_data_len,
    unsigned char* plain_data, int max_plain_buf_len);

    /**
     * @brief RSA Sign Data from Private key (SHA-256)
     * @param priv_key   private key (DER/PEM)
     * @param priv_key_len private key length
     * @param hash       input data (hashed data)
     * @param hash_len   input data length
     * @param signature_data    output signature buffer
     * @param max_signature_len maximum signature buffer length
     * @return Success: signature length, Fail: -1
    */
    int rsa_sign(const unsigned char* priv_key, int priv_key_len, const unsigned char* hash, int hash_len,
                          unsigned char* signature_data, int max_sig_len);

    /**
     * @brief RSA Verify Signature (SHA-256)
     * @param pub_key   public key (DER/PEM)
     * @param pub_key_len public key length
     * @param hash      input data (hashed data)
     * @param hash_len  input data length
     * @param signature       input signature
     * @param signature_len   signature length
     * @return Success: 1, Fail: 0
     */
    int rsa_verify(const unsigned char* pub_key, int pub_key_len, const unsigned char* hash, int hash_len,
                          const unsigned char* signature, int signature_len);

  
  };

  #endif /* __CIPHER_HPP */