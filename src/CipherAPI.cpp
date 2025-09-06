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

#include "Define.h"
#include "CipherAPI.h"

// openssl 3.0 prev 1.1.1 use warning disable
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/**
* @brief make hash value SHA-256
* @param data plain data
* @param hashed output hash data (~64byte)
* @param hash_buf_max_size hash buffer max size
* @param type algorithm type ALG_SHA256: 0, ALG_SHA512: 1
* @return Success: hash length fail: -1
*/
int CipherAPI::hash_make_value(char* data, unsigned char* hashed, int hash_buf_max_size, int type){

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();

  if (!ctx){
      return FAIL;
  }

  // algorithm setting check
  const EVP_MD* md = nullptr;
  switch (type) {
      case ALG_SHA256: md = EVP_sha256(); break;
      case ALG_SHA512: md = EVP_sha512(); break;
      default:
          DBG_PRINT("HASH Algorithm Invalid\n");
          return FAIL;
  }

  // hash output buffer size check
  int required_size = EVP_MD_size(md);
  if (hash_buf_max_size < required_size) {
    EVP_MD_CTX_free(ctx);
    DBG_PRINT("hash make buffer enough \n");
    return FAIL;
  }

  EVP_DigestInit_ex(ctx, md, NULL);
  EVP_DigestUpdate(ctx, data, strlen(data));

  unsigned int hashed_len;
  EVP_DigestFinal_ex(ctx, hashed, &hashed_len);
  EVP_MD_CTX_free(ctx);

  return hashed_len;
}

/**
* @brief Symmetry encryption data
* @param data input plain data
* @param key key data
* @param iv inital vector
* @param enc_buf output buffer
* @param max_buf_size output buffer max size
* @return Success: enc_buf len, fail -1
*/
int CipherAPI::enc_sym_data(const char* data, unsigned char* key, unsigned char* iv, int type, unsigned char* enc_buf, int max_buf_size){

  // Encryption create context
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    DBG_PRINT("encryption ctx fail \n");
    return FAIL;
  }

  // algorithm setting check
  const EVP_CIPHER* cipher = nullptr;
  switch (type) {
      case ALG_ARIA128: cipher = EVP_aria_128_cbc(); break;
      case ALG_ARIA192: cipher = EVP_aria_192_cbc(); break;
      case ALG_ARIA256: cipher = EVP_aria_256_cbc(); break;
      case ALG_AES128: cipher = EVP_aes_128_cbc(); break;
      case ALG_AES192: cipher = EVP_aes_192_cbc(); break;
      case ALG_AES256: cipher = EVP_aes_256_cbc(); break;
      default:
          DBG_PRINT("HASH Algorithm Invalid\n");
          return FAIL;
  }

  // Encryption init
  if(!EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv)){
    EVP_CIPHER_CTX_free(ctx);
    DBG_PRINT("encryption init fail \n");
    return FAIL;
  }

  // Encryption update
  int len;
  int ciphertext_len;
  if(!EVP_EncryptUpdate(ctx, enc_buf, &len, (unsigned char*)data, strlen(data))){
    EVP_CIPHER_CTX_free(ctx);
    DBG_PRINT("encryption update fail \n");
    return FAIL;
  }

  ciphertext_len = len;

  // Encryption final
  if(!EVP_EncryptFinal_ex(ctx, enc_buf + len, &len)){
    EVP_CIPHER_CTX_free(ctx);
    DBG_PRINT("encryption final ex fail \n");
    return FAIL;
  }

  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  // check buffer size
  if (ciphertext_len > max_buf_size) {
    DBG_PRINT("buffer size not enough \n");
    return FAIL;
  }

  return ciphertext_len;
}

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
int CipherAPI::dec_sym_data(unsigned char* enc_buf, int enc_buf_len, unsigned char* key, unsigned char* iv, int type, unsigned char* dec_buf, int max_buf_size){

  // Decryption create context
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    DBG_PRINT("decryption ctx fail \n");
    return FAIL;
  }

  // algorithm setting check
  const EVP_CIPHER* cipher = nullptr;
  switch (type) {
      case ALG_ARIA128: cipher = EVP_aria_128_cbc(); break;
      case ALG_ARIA192: cipher = EVP_aria_192_cbc(); break;
      case ALG_ARIA256: cipher = EVP_aria_256_cbc(); break;
      case ALG_AES128: cipher = EVP_aes_128_cbc(); break;
      case ALG_AES192: cipher = EVP_aes_192_cbc(); break;
      case ALG_AES256: cipher = EVP_aes_256_cbc(); break;
      default:
          DBG_PRINT("HASH Algorithm Invalid\n");
          return FAIL;
  }

  // Decryption init
  if (!EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    DBG_PRINT("decryption init fail \n");
    return FAIL;
  }

  // Decryption update
  int len;
  int plaintext_len;
  if (!EVP_DecryptUpdate(ctx, dec_buf, &len, enc_buf, enc_buf_len)) {
    EVP_CIPHER_CTX_free(ctx);
    DBG_PRINT("decryption update fail \n");
    return FAIL;
  }

  plaintext_len = len;

  // Decryption final
  if (!EVP_DecryptFinal_ex(ctx, dec_buf + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    DBG_PRINT("decryption final ex fail \n");
    return FAIL;
  }

  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  // check buffer size
  if (plaintext_len >= max_buf_size) {
    DBG_PRINT("buffer size not enough \n");
    return FAIL;
  }

  return plaintext_len;
}

/**
* @brief Generate PBKDF2 Key
* @param password drive key password
* @param salt salt data
* @param salt_len salt length
* @param key output key buffer
* @param key_len key length
* @return Success: 0 len, fail -1
*/ 
int CipherAPI::pbkdf_key_generate(const char* password, unsigned char* salt, int salt_len, unsigned char* key, int key_len){

  // generate salt
  if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len, PBKDF2_ITER, EVP_sha256(), key_len, key) != 1) {
    DBG_PRINT("pbkdf2 key generate fail \n");
    return FAIL;
  }

  DBG_PRINT("pbkdf2 key generate success \n");
  return SUCCESS;
}

/**
* @brief Generate RSA Key Context
* @param key_size key size
* @param e_number RSA e module
* @return Success: 0 len, fail -1
*/
RSA* CipherAPI::generate_rsa_key_pair(int key_size, unsigned int e_number) {

  // new Context
  RSA* rsa = RSA_new();
  BIGNUM* e = BN_new();

  if (!rsa || !e) { //Init Check
    RSA_free(rsa);
    BN_free(e);
    return nullptr;
  }

  // setting openssl member RSA e moduler number
  BN_set_word(e, e_number);

  // generate key
  if (RSA_generate_key_ex(rsa, key_size, e, nullptr) != 1) {
    DBG_PRINT("RSA key Generate Fail\n");
    BN_free(e);
    return nullptr;
  }
  DBG_PRINT("RSA key Generate Success\n");
  BN_free(e);
  return rsa;
}

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
int CipherAPI::generate_rsa_key_pair_der(int key_size, unsigned int e_number, unsigned char* out_priv, int& out_priv_len, int max_priv_buf,
                                  unsigned char* out_pub,  int& out_pub_len,  int max_pub_buf){

  out_priv_len = 0;
  out_pub_len  = 0;
  RSA* rsa = nullptr;

  // Key Context Generate
  rsa = generate_rsa_key_pair(key_size, e_number);
  if (!rsa){
    RSA_free(rsa);
    return FAIL;
  }

  // Private Key DER Encoading
  // get length output data
  int priv_len = i2d_RSAPrivateKey(rsa, nullptr);
  if (priv_len <= 0 || priv_len > max_priv_buf){
    DBG_PRINT("Convert RSA Private Key Fail \n");
    RSA_free(rsa);
    return FAIL;
  }

  // get data inner buffer
  unsigned char* pri_ptr = out_priv;
  if (i2d_RSAPrivateKey(rsa, &pri_ptr) != priv_len){
    DBG_PRINT("Convert RSA Private Key Fail \n");
    RSA_free(rsa);
    return FAIL;
  }
  out_priv_len = priv_len;

  // Public Key DER Encoading
  // get length output data
  int pub_len = i2d_RSA_PUBKEY(rsa, nullptr);
  if (pub_len <= 0 || pub_len > max_pub_buf){
    DBG_PRINT("Convert RSA Public Key Fail \n");
    RSA_free(rsa);
    return FAIL;
  }

  // get data inner buffer
  unsigned char* pub_ptr = out_pub;
  if (i2d_RSA_PUBKEY(rsa, &pub_ptr) != pub_len){
    DBG_PRINT("Convert RSA Public Key Fail \n");
    RSA_free(rsa);
    return FAIL;
  }
  out_pub_len = pub_len;

  DBG_PRINT("Convert RSA Key Success \n");
  RSA_free(rsa);
  return SUCCESS;
}

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
int CipherAPI::rsa_encrypt(const unsigned char* pub_key, int pub_key_len, const unsigned char* plain_data, int plain_data_len,
                            unsigned char* enc_data, int max_enc_buf_len){

    // Get Public Key
    const unsigned char* p = pub_key; // move inner function
    RSA* rsa = nullptr;
    rsa = d2i_RSA_PUBKEY(nullptr, &p, pub_key_len);
    if (!rsa){
      DBG_PRINT("public key context get fail \n");
      return FAIL;
    }

    int enc_data_len = RSA_public_encrypt(plain_data_len, plain_data, enc_data, rsa, RSA_PKCS1_PADDING);
    if (enc_data_len <= 0 || enc_data_len > max_enc_buf_len) {
      DBG_PRINT("RSA Encryption fail %d \n", enc_data_len);
      RSA_free(rsa);
      return FAIL;
    }

    DBG_PRINT("RSA Encrypted \n");
    RSA_free(rsa);
    return enc_data_len;
}

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
int CipherAPI::rsa_decrypt(const unsigned char* priv_key, int priv_key_len, const unsigned char* enc_data, int enc_data_len,
    unsigned char* plain_data, int max_plain_buf_len){

    // Get Private Key
    const unsigned char* p = priv_key; // move inner function
    RSA* rsa = nullptr;
    rsa = d2i_RSAPrivateKey(nullptr, &p, priv_key_len);
    if (!rsa){
      DBG_PRINT("private key context get fail \n");
      return FAIL;
    }

    // RSA Decryption
    int plain_data_len = RSA_private_decrypt(enc_data_len, enc_data, plain_data, rsa, RSA_PKCS1_PADDING);
    if (plain_data_len <= 0 || plain_data_len > max_plain_buf_len) {
      DBG_PRINT("RSA Decryption fail %d \n", plain_data_len);
      RSA_free(rsa);
      return FAIL;
    }

    DBG_PRINT("RSA Decrypted \n");
    RSA_free(rsa);
    return plain_data_len;
}

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
int CipherAPI::rsa_sign(const unsigned char* priv_key, int priv_key_len, const unsigned char* hash, int hash_len,
                          unsigned char* signature_data, int max_sig_len){

    // Get Private Key
    const unsigned char* p = priv_key; // move inner function
    RSA* rsa = nullptr;
    rsa = d2i_RSAPrivateKey(nullptr, &p, priv_key_len);
    if (!rsa){
      DBG_PRINT("private key context get fail \n");
      return FAIL;
    }

    if (max_sig_len < RSA_size(rsa)) {
        DBG_PRINT("buffer too small for signature\n");
        RSA_free(rsa);
        return FAIL;
    }

    unsigned int signature_len = 0;
    if (RSA_sign(NID_sha256, hash, hash_len, signature_data, &signature_len, rsa) != 1) {
        DBG_PRINT("RSA_sign failed\n");
        RSA_free(rsa);
        return FAIL;
    }

    RSA_free(rsa);
    return (int)signature_len;
}


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
int CipherAPI::rsa_verify(const unsigned char* pub_key, int pub_key_len, const unsigned char* hash, int hash_len,
                          const unsigned char* signature, int signature_len){
    // Get Public Key
    const unsigned char* p = pub_key; // move inner function
    RSA* rsa = nullptr;
    rsa = d2i_RSA_PUBKEY(nullptr, &p, pub_key_len);
    if (!rsa){
      DBG_PRINT("public key context get fail \n");
      return FAIL;
    }

    int ret = RSA_verify(NID_sha256, hash, hash_len, signature, signature_len, rsa);
    RSA_free(rsa);
    if (ret == 1) {
      DBG_PRINT("RSA Verify success\n");
      return SUCCESS;
    } else {
      DBG_PRINT("RSA Verify fail\n");
      return FAIL;
    }
}

/**
* @brief generate random key
* @param data output data buffer
* @param len output hash data
* @return Success: 0 Fail -1
*/
int CipherAPI::generate_rand_data(unsigned char* data, int len){

    if (RAND_bytes(data, len) != 1) {
        DBG_PRINT("Random data generated fail \n");
        return FAIL;
    }
    DBG_PRINT("Random Data Generate \n");
    return SUCCESS;
}