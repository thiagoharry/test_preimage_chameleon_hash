#include <stdio.h>
#include "test_bliss.h"
#include "libstrongswan/library.h"

#define N 2 // Number of times we measure each function
#include "timer.h"


static u_int key_strength[] = { 128, 160, 192 };


void fill_random_string(char *str, int size){
  FILE *randomData = fopen("/dev/urandom", "r");
  int r;
  //ifstream urandom("/dev/urandom", ios::in|ios::binary);
  //urandom.read(reinterpret_cast<char*>(str), size);
  //urandom.close();
  r = fread(str, 1, size - 1, randomData);
  str[r] = '\0';
  fclose(randomData);
}


void test_bliss(u_int key_type){
  int i;
  private_key_t *privkey;
  public_key_t *pubkey;
  chunk_t signature;
  size_t signature_size, pk_size, sk_size;;
  
  printf("========== BLISS-B I Signature \n");

  
  library_init(NULL, "preimage");
  if(!lib->plugins->load(lib->plugins, "random! sha1! sha2! mgf1! sha3! bliss!")){
    fprintf(stderr, "ERROR: Failed to load BLISS Plugin. Skipping test.\n");
    return;
  }

  for(i = 0; i < N; i ++){
    TIMER_BEGIN();
    privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_BLISS,
				 BUILD_KEY_SIZE, key_type, BUILD_END);
    pubkey = privkey->get_public_key(privkey);
    TIMER_END();
    privkey->destroy(privkey);
    pubkey->destroy(pubkey);
  }
  TIMER_RESULT("KeyGen");


  for(i = 0; i < N; i ++){
    char msg[128];
    chunk_t msg2;
    privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_BLISS,
				 BUILD_KEY_SIZE, key_type, BUILD_END);
    pubkey = privkey->get_public_key(privkey);
    fill_random_string(msg, 128);
    msg2 =  chunk_create(msg, 128);
    TIMER_BEGIN();
    privkey->sign(privkey, SIGN_BLISS_WITH_SHA2_256, NULL, msg2,
		  &signature);
    TIMER_END();
    free(signature.ptr);
    privkey->destroy(privkey);
    pubkey->destroy(pubkey);
  }
  TIMER_RESULT("Sign");


  for(i = 0; i < N; i ++){
    char msg[128];
    chunk_t msg2;
    int verify;
    privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_BLISS,
				 BUILD_KEY_SIZE, key_type, BUILD_END);
    pubkey = privkey->get_public_key(privkey);
    fill_random_string(msg, 128);
    msg2 =  chunk_create(msg, 128);
    privkey->sign(privkey, SIGN_BLISS_WITH_SHA2_256, NULL, msg2,
		  &signature);
    TIMER_BEGIN();
    verify = pubkey->verify(pubkey, SIGN_BLISS_WITH_SHA2_256, NULL, msg2,
			    signature);
    TIMER_END();
    if(!verify){
      fprintf(stderr, "ERROR: BLISS Signature failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    }
    signature_size = signature.len;
    
    free(signature.ptr);
    privkey->destroy(privkey);
    pubkey->destroy(pubkey);
  }
  TIMER_RESULT("Verify");

  printf("'σ'    size: %d bytes\n", (int) signature_size);
  {
    chunk_t enc;
    privkey = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_BLISS,
				 BUILD_KEY_SIZE, key_type, BUILD_END);
    pubkey = privkey->get_public_key(privkey);
    pubkey->get_encoding(pubkey, PUBKEY_ASN1_DER, &enc);
    pk_size = enc.len;
    free(enc.ptr);
    privkey->get_encoding(privkey, PRIVKEY_ASN1_DER, &enc);
    sk_size = enc.len;
    free(enc.ptr);
    privkey->destroy(privkey);
    pubkey->destroy(pubkey);
  }
  /*pk_size =  512 *
    4 *
    2;*/
  printf("'PK'    size: %d bytes\n", (int) pk_size);
  /*sk_size = pk_size + // A and Ar also appear in SK
    2 * // s1 and s2
    1 * // both are 8 bit balues
    512; // n size in BLISS-B I*/
  printf("'SK'    size: %d bytes\n", (int) sk_size);
  
  lib->plugins->unload(lib->plugins);
  return;
}
