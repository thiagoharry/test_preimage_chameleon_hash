#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "dilithium/randombytes.h"
#include "dilithium/sign.h"
#include "test_dilithium.h"

#define MLEN 128
#define NTESTS 1000

#include "timer.h"

static void fill_random_string(unsigned char *str, int size){
  FILE *randomData = fopen("/dev/urandom", "r");
  int r;
  r = fread(str, 1, size - 1, randomData);
  str[r] = '\0';
  fclose(randomData);
}


int test_dilithium(void){
  unsigned int i;
  int ret;
  size_t mlen, smlen;
  unsigned char m[MLEN];
  uint8_t sm[MLEN + CRYPTO_BYTES];
  uint8_t m2[MLEN + CRYPTO_BYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  printf("========== Dilithium 1280x1024 Signature \n");
  for(i = 0; i < NTESTS; i ++){
    TIMER_BEGIN();
    crypto_sign_keypair(pk, sk);
    TIMER_END();
  }
  TIMER_RESULT("KeyGen");

  for(i = 0; i < NTESTS; i ++){
    crypto_sign_keypair(pk, sk);
    fill_random_string(m, MLEN);
    TIMER_BEGIN();
    crypto_sign(sm, &smlen, m, MLEN, sk);
    TIMER_END();
  }
  TIMER_RESULT("Sign");

  for(i = 0; i < NTESTS; i ++){
    crypto_sign_keypair(pk, sk);
    fill_random_string(m, MLEN);
    crypto_sign(sm, &smlen, m, MLEN, sk);
    TIMER_BEGIN();
    ret = crypto_sign_open(m2, &mlen, sm, smlen, pk);
    TIMER_END();
    if(ret){
      fprintf(stderr, "ERROR: Dilihium signature failed!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    }
  }
  TIMER_RESULT("Verify");

  printf("'σ'    size: %d bytes\n", (int) mlen);
  printf("'PK'   size: %d bytes\n", CRYPTO_PUBLICKEYBYTES);
  printf("'SK'   size: %d bytes\n", CRYPTO_SECRETKEYBYTES);
  return 0;
}
