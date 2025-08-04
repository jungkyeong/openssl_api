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
      return 0;
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
    std::cout << "encryption ctx fail" << std::endl;
    return -1;
  }

  // Encryption init
  if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)){
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "encryption init fail" << std::endl;
    return -1;
  }

  // Encryption update
  int len;
  int ciphertext_len;
  if(!EVP_EncryptUpdate(ctx, enc_buf, &len, (unsigned char*)data, strlen(data))){
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "encryption update fail" << std::endl;
    return -1;
  }

  ciphertext_len = len;

  // Encryption final
  if(!EVP_EncryptFinal_ex(ctx, enc_buf + len, &len)){
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "encryption final ex fail" << std::endl;
    return -1;
  }

  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  // check buffer size
  if (ciphertext_len > max_buf_size) {
    std::cout << "buffer size not enough" << std::endl;
    return -1;
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
    std::cout << "decryption ctx fail" << std::endl;
    return -1;
  }

  // Decryption init
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "decryption init fail" << std::endl;
    return -1;
  }

  // Decryption update
  int len;
  int plaintext_len;
  if (!EVP_DecryptUpdate(ctx, dec_buf, &len, enc_buf, enc_buf_len)) {
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "decryption update fail" << std::endl;
    return -1;
  }

  plaintext_len = len;

  // Decryption final
  if (!EVP_DecryptFinal_ex(ctx, dec_buf + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    std::cout << "decryption final ex fail" << std::endl;
    return -1;
  }

  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  // check buffer size
  if (plaintext_len >= max_buf_size) {
    std::cout << "buffer size not enough" << std::endl;
    return -1;
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
    std::cout << "salt generate fail" << std::endl; 
    return -1;
  }

  // generate salt
  if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_LEN, PBKDF2_ITER, EVP_sha256(), key_len, key) != 1) {
    std::cout << "pbkdf2 key generate fail" << std::endl; 
    return -1;
  }

  std::cout << "pbkdf2 key generate success" << std::endl;
  return 0;
}