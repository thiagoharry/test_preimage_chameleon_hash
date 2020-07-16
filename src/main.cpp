//#include <palisade.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <signaturecontext.h>
#include <fstream>
#include "chameleon_hash.h"
#include "context.h"


#define N 1000 // Number of times we measure each function
#include "timer.h"

using namespace lbcrypto;

void sha256_string(const char *string, char outputBuffer[65]){
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, string, strlen(string));
  SHA256_Final(hash, &sha256);
  int i = 0;
  for(i = 0; i < SHA256_DIGEST_LENGTH; i++){
    sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
  }
  outputBuffer[64] = 0;
}

string get_random_string(void){
  char s[128];
  ifstream urandom("/dev/urandom", ios::in|ios::binary);
  urandom.read(reinterpret_cast<char*>(&s), 128);
  urandom.close();
  s[127] = '\0';
  return string(s);
}

size_t palisade_vector_size(NativePoly v){
  return v.GetLength() * (int) (ceil(ceil(log2(v.GetModulus().ConvertToDouble()))/8.0));
}

size_t palisade_matrix_size(Matrix<NativePoly> m){
  return m.GetRows() * m.GetCols() * palisade_vector_size(m(0, 0));
}

void test_chameleon_hash(usint ringsize, usint bits, usint base){
  ChameleonHashContext<NativePoly> context;
  SignatureContext<NativePoly> test_context;
  int i;

  context.GenerateGPVContext(ringsize, bits, base);
  test_context.GenerateGPVContext(ringsize, bits, base);

  GPVVerificationKey<NativePoly> vk;
  GPVSignKey<NativePoly> sk;

  printf("========== PREIMAGE CHAMELEON HASH (n=%d, bits de k=%d, base=%d)\n",
	 ringsize, bits, base);
  
  // The key generation is the same than in GPV signature. We prefer
  // to measure the original function because in the GPV context we
  // used a nonstandard seed function to deal with a conflict in the
  // linking phase
  for(i = 0; i < N; i ++){
    TIMER_BEGIN();
    test_context.KeyGen(&sk,&vk);
    TIMER_END();
  }
  TIMER_RESULT("KeyGen");

  // Generating the final keys.
  context.KeyGen(&sk,&vk);

  // In a final implementation a better function to generate a random
  // parameter 'r' without needing the trapdoor should be used
  GPVSignature<NativePoly> r;
  context.GetRandomParameter(sk,vk,&r);

  // Measuring hash 
  NativePoly digest1;
  for(i = 0; i < N; i ++){
    string pt = get_random_string();
    GPVPlaintext<NativePoly> plaintext(pt);
    TIMER_BEGIN();
    context.Hash(plaintext,r,vk, &digest1);
    TIMER_END();
  }
  TIMER_RESULT("Hash");

  // Measuring preimage
  GPVSignature<NativePoly> r2;
  NativePoly digest2;
  for(i = 0; i < N; i ++){
    string pt2 = get_random_string();
    GPVPlaintext<NativePoly> plaintext2(pt2);
    TIMER_BEGIN();
    context.Preimage(plaintext2, digest1, sk, vk, &r2);
    TIMER_END();
    if(i == N - 1)
      context.Hash(plaintext2,r2,vk, &digest2);
  }
  TIMER_RESULT("Preimage");

  // Just checking that the result is correct:
  {
    if(digest1 != digest2){
      std::cout << "ERROR: Preimage returned incorrect value!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl ;
    }
    string pt = get_random_string();
    GPVPlaintext<NativePoly> plaintext(pt);
    NativePoly digest3;
    context.Hash(plaintext,r2,vk, &digest3);
    if(digest3 == digest2){
      std::cout << "ERROR: New collision found without trapdoor! This is shouldn't happen except with negligible probabilty!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl ;
    }
  }


  
    //std::cout << digest1[5] << std::endl;
  std::cout << "Digest size: " << palisade_vector_size(digest1) << " bytes" << std::endl;
  std::cout << "'R'    size: " << palisade_matrix_size(r2.GetSignature()) << " bytes" << std::endl;
  std::cout << "'PK'   size: " << palisade_matrix_size(vk.GetVerificationKey()) << " bytes" << std::endl;
  std::cout << "'SK'   size: " << palisade_matrix_size(sk.GetSignKey().m_r) + palisade_matrix_size(sk.GetSignKey().m_e) << " bytes" << std::endl;
}

void test_chameleon_hash_512(void){
  test_chameleon_hash(512, 24, 8);
}

void test_chameleon_hash_1024(void){
  test_chameleon_hash(1024, 27, 64);
}

void test_rsa(int n){
  RSA *rsa;
  EVP_PKEY *pkey;
  BIGNUM *bn;
  int i;
  unsigned int signature_size;
  printf("========== RSA SIGNATURE (n=%d)\n", n);
  pkey = EVP_PKEY_new();
  rsa = RSA_new();
  bn = BN_new();
  BN_set_word(bn, RSA_F4);
  for(i = 0; i < N; i ++){
    TIMER_BEGIN();
    RSA_generate_key_ex(rsa, n, bn, NULL);
    TIMER_END();
    EVP_PKEY_assign_RSA(pkey, rsa);
    EVP_PKEY_free(pkey);
    pkey = EVP_PKEY_new();
    rsa = RSA_new();
  }
  TIMER_RESULT("KeyGen");
  RSA_generate_key_ex(rsa, n, bn, NULL);
  EVP_PKEY_assign_RSA(pkey, rsa);

  for(i = 0; i < N; i ++){
    unsigned char encMessage[2048];
    unsigned int encMessageLength;
    string plainText = get_random_string();
    char digest[65];
    TIMER_BEGIN();
    sha256_string(plainText.c_str(), digest);
    RSA_sign(NID_sha256, (const unsigned char *) digest, 65, &encMessage[0],
	     &encMessageLength, rsa);
    TIMER_END();
  }
  TIMER_RESULT("Sign");

  for(i = 0; i < N; i ++){
    unsigned char encMessage[2048];
    unsigned int encMessageLength;
    string plainText = get_random_string();
    char digest[65];
    int verif;
    sha256_string(plainText.c_str(), digest);
    RSA_sign(NID_sha256, (const unsigned char *) digest, 65, &encMessage[0],
	     &encMessageLength, rsa);
    TIMER_BEGIN();
    verif = RSA_verify(NID_sha256, (const unsigned char *) digest, 65,
	       &encMessage[0], encMessageLength, rsa);
    TIMER_END();
    signature_size = encMessageLength;
    if(verif == 0)
      fprintf(stderr, "ERROR: RSA with wrong signature!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
  }
  TIMER_RESULT("Verify");
  std::cout << "'σ'    size: " << signature_size << " bytes" << std::endl;

  {
    const BIGNUM *n, *e, *d;
    RSA_get0_key(rsa, &n, &e, &d);
    std::cout << "'PK'   size: " << BN_num_bytes(n) + BN_num_bytes(e) << " bytes" << std::endl;
    std::cout << "'SK'   size: " << BN_num_bytes(n) + BN_num_bytes(d) << " bytes" << std::endl;
  }
  EVP_PKEY_free(pkey);
}

void test_ecdsa(int nid){
  EC_KEY    *key = NULL;
  ECDSA_SIG *signature = NULL;
  int i;
  size_t signature_size;
  printf("========== ECDSA SIGNATURE (curve=%d)\n", nid);

  for(i = 0; i < N; i ++){
    key = EC_KEY_new_by_curve_name(nid);
    TIMER_BEGIN();
    EC_KEY_generate_key(key);
    TIMER_END();
    EC_KEY_free(key);
  }
  TIMER_RESULT("KeyGen");

  key = EC_KEY_new_by_curve_name(nid);
  EC_KEY_generate_key(key);

  for(i = 0; i < N; i ++){
    string plainText = get_random_string();
    char digest[65];
    TIMER_BEGIN();
    sha256_string(plainText.c_str(),  digest);
    signature = ECDSA_do_sign((const unsigned char *) digest, 65, key);
    TIMER_END();
    ECDSA_SIG_free(signature);
  }
  TIMER_RESULT("Sign");

  for(i = 0; i < N; i ++){
    string plainText = get_random_string();
    char digest[65];
    int verif;
    const BIGNUM *r, *s;
    sha256_string(plainText.c_str(),  digest);
    signature = ECDSA_do_sign((const unsigned char *) digest, 65, key);
    TIMER_BEGIN();
    verif = ECDSA_do_verify((const unsigned char *) digest, 65, signature, key);
    TIMER_END();
    if(verif == 0)
      fprintf(stderr, "ERROR: RSA with wrong signature!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    ECDSA_SIG_get0(signature, &r, &s);
    signature_size = BN_num_bytes(r) + BN_num_bytes(s);
    ECDSA_SIG_free(signature);
  }
  TIMER_RESULT("Verify");

  std::cout << "'σ'    size: " << signature_size << " bytes" << std::endl;

  {
    const EC_POINT *pk = EC_KEY_get0_public_key(key);
    unsigned char *buf;
    EC_GROUP	*group;
    BN_CTX *bnctx = BN_CTX_new();
    size_t size;
    group = EC_GROUP_new_by_curve_name(nid);
    size = EC_POINT_point2buf(group, pk, POINT_CONVERSION_COMPRESSED, &buf, bnctx);
    std::cout << "'PK'   size: " << size << " bytes" << std::endl;
    OPENSSL_free(buf);
    BN_CTX_free(bnctx);
  }

  
  {
    const BIGNUM *sk = EC_KEY_get0_private_key(key);
    std::cout << "'SK'   size: " << BN_num_bytes(sk) << " bytes" << std::endl;
  }


  EC_KEY_free(key);
}

int main(int argc, char **argv){

  test_rsa(1024);
  test_ecdsa(NID_X9_62_prime192v1);
  test_chameleon_hash_512();
  test_chameleon_hash_1024();

  
  return 0;
}
