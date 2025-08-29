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

/**
* @brief make hash value SHA-256
* @param data plain data
* @param hashed output hash data(32byte)
* @return Success: hash length(32) fail: 0
*/
int CipherAPI::hash_make_value(char* data, unsigned char* hashed){

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();

  if (!ctx){
      return FAIL;
  }

  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
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
int CipherAPI::enc_sym_data(const char* data, unsigned char* key, unsigned char* iv, unsigned char* enc_buf, int max_buf_size){

  // Encryption create context
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if(!ctx){
    DBG_PRINT("encryption ctx fail \n");
    return FAIL;
  }

  // Encryption init
  if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
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
int CipherAPI::dec_sym_data(unsigned char* enc_buf, int enc_buf_len, unsigned char* key, unsigned char* iv, unsigned char* dec_buf, int max_buf_size){

  // Decryption create context
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    DBG_PRINT("decryption ctx fail \n");
    return FAIL;
  }

  // Decryption init
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
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
* @param key output key buffer
* @param key_len key length
* @return Success: 0 len, fail -1
*/ 
int CipherAPI::pbkdf_key_generate(const char* password, unsigned char* key, int key_len){

  // create random salt value
  unsigned char salt[SALT_LEN];
  if (RAND_bytes(salt, SALT_LEN) != 1) {
    DBG_PRINT("salt generate fail \n");
    return FAIL;
  }

  // generate salt
  if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, PBKDF2_ITER, EVP_sha256(), key_len, key) != 1) {
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