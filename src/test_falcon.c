#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define EXPAND_SECRET_KEY
#define NTESTS 1000
#include "timer.h"

#include "falcon/falcon.h"

static void fill_random_string(unsigned char *str, int size){
  FILE *randomData = fopen("/dev/urandom", "r");
  int r;
  r = fread(str, 1, size - 1, randomData);
  str[r] = '\0';
  fclose(randomData);
}

static inline size_t
maxsz(size_t a, size_t b){
  return a > b ? a : b;
}

static void *
xmalloc(size_t len){
  void *buf;
  if (len == 0) {
    return NULL;
  }
  buf = malloc(len);
  if (buf == NULL) {
    fprintf(stderr, "memory allocation error\n");
    exit(EXIT_FAILURE);
  }
  return buf;
}

static void
xfree(void *buf){
  if (buf != NULL) {
    free(buf);
  }
}


typedef struct {
	unsigned logn;
	shake256_context rng;
	uint8_t *tmp;
	size_t tmp_len;
	uint8_t *pk;
	uint8_t *sk;
	uint8_t *esk;
	uint8_t *sig;
	size_t sig_len;
	uint8_t *sigct;
	size_t sigct_len;
} bench_context;



void test_falcon(void){
  int i;
  bench_context bc;
  size_t len, signature_size = 99999999999999999;
  unsigned char m[128];
  int v1, v2;
  printf("========== FALCON-512 Signature \n");
  bc.logn = 9; // Using FALCON-512 and allocating its buffers and RNG
  if (shake256_init_prng_from_system(&bc.rng) != 0) {
    fprintf(stderr, "random seeding failed\n");
    exit(EXIT_FAILURE);
  }
  len = FALCON_TMPSIZE_KEYGEN(bc.logn);
  len = maxsz(len, FALCON_TMPSIZE_SIGNDYN(bc.logn));
  len = maxsz(len, FALCON_TMPSIZE_SIGNTREE(bc.logn));
  len = maxsz(len, FALCON_TMPSIZE_EXPANDPRIV(bc.logn));
  len = maxsz(len, FALCON_TMPSIZE_VERIFY(bc.logn));
  bc.tmp = xmalloc(len);
  bc.tmp_len = len;
  bc.pk = xmalloc(FALCON_PUBKEY_SIZE(bc.logn));
  bc.sk = xmalloc(FALCON_PRIVKEY_SIZE(bc.logn));
  bc.esk = xmalloc(FALCON_EXPANDEDKEY_SIZE(bc.logn));
  bc.sig = xmalloc(FALCON_SIG_VARTIME_MAXSIZE(bc.logn));
  bc.sig_len = FALCON_SIG_VARTIME_MAXSIZE(bc.logn);
  bc.sigct = xmalloc(FALCON_SIG_CT_SIZE(bc.logn));
  bc.sigct_len = 0;

  for(i = 0; i < NTESTS; i ++){
    TIMER_BEGIN();
    v1 = falcon_keygen_make(&bc.rng, bc.logn,
			    bc.sk, FALCON_PRIVKEY_SIZE(bc.logn),
			    bc.pk, FALCON_PUBKEY_SIZE(bc.logn),
			    bc.tmp, bc.tmp_len);
    TIMER_END();
    if(v1 < 0){
      fprintf(stderr, "ERROR: FALCON failed creating keys!!!!!!!!!!\n");
      exit(1);
    }
  }
  TIMER_RESULT("KeyGen");

  for(i = 0; i < NTESTS; i ++){
    falcon_keygen_make(&bc.rng, bc.logn,
		       bc.sk, FALCON_PRIVKEY_SIZE(bc.logn),
		       bc.pk, FALCON_PUBKEY_SIZE(bc.logn),
		       bc.tmp, bc.tmp_len);
    fill_random_string(m, 128);
    v1 = 0;
    bc.sig_len = FALCON_SIG_VARTIME_MAXSIZE(bc.logn);
    TIMER_BEGIN();
#ifdef EXPAND_SECRET_KEY
    v1 = falcon_expand_privkey(bc.esk, FALCON_EXPANDEDKEY_SIZE(bc.logn),
			      bc.sk, FALCON_PRIVKEY_SIZE(bc.logn),
			      bc.tmp, bc.tmp_len);
    v2 = falcon_sign_tree(&bc.rng, bc.sig, &bc.sig_len,
			  bc.esk, m, 128, 0, bc.tmp, bc.tmp_len);
#else
    v2 = falcon_sign_dyn(&bc.rng, bc.sig, &bc.sig_len, bc.sk,
		    FALCON_PRIVKEY_SIZE(bc.logn),
		    m, 128, 0, bc.tmp, bc.tmp_len);
#endif
    TIMER_END();
    if(bc.sig_len < signature_size)
      signature_size = bc.sig_len;
    if(v1 < 0){
      fprintf(stderr, "ERROR: FALCON-512 failed expanding key (%d)!!!!!!!!!!!!!!!!!!!!!!!!!!\n", v1);
      exit(1);
    }
    if(v2 < 0){
      fprintf(stderr, "ERROR: FALCON-512 failed signing (%d)!!!!!!!!!!!!!!!!!!!!!!!!!!\n", v2);
      exit(1);
    }
  }
  TIMER_RESULT("Sign");


  for(i = 0; i < NTESTS; i ++){
    falcon_keygen_make(&bc.rng, bc.logn,
		       bc.sk, FALCON_PRIVKEY_SIZE(bc.logn),
		       bc.pk, FALCON_PUBKEY_SIZE(bc.logn),
		       bc.tmp, bc.tmp_len);
    fill_random_string(m, 128);
    bc.sig_len = FALCON_SIG_VARTIME_MAXSIZE(bc.logn);
#ifdef EXPAND_SECRET_KEY
    falcon_expand_privkey(bc.esk, FALCON_EXPANDEDKEY_SIZE(bc.logn),
			  bc.sk, FALCON_PRIVKEY_SIZE(bc.logn),
			  bc.tmp, bc.tmp_len);
    falcon_sign_tree(&bc.rng, bc.sig, &bc.sig_len,
		     bc.esk,	m, 128, 0, bc.tmp, bc.tmp_len);
#else
    falcon_sign_dyn(&bc.rng, bc.sig, &bc.sig_len, bc.sk,
		    FALCON_PRIVKEY_SIZE(bc.logn),
		    m, 128, 0, bc.tmp, bc.tmp_len);
#endif
    TIMER_BEGIN();
    v1 = falcon_verify(bc.sig, bc.sig_len, bc.pk, FALCON_PUBKEY_SIZE(bc.logn),
		      m, 128, bc.tmp, bc.tmp_len);
    TIMER_END();
    if(v1 < 0){
      fprintf(stderr, "ERROR: FALCON-512 failed veryifing the signature!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
      exit(1);
    }
  }
  TIMER_RESULT("Verify");
  
  printf("'σ'    size: %d bytes\n", (int) signature_size);
  printf("'PK'   size: %d bytes\n", (int) FALCON_PUBKEY_SIZE(bc.logn));
  printf("'SK'   size: %d bytes\n", (int) FALCON_PRIVKEY_SIZE(bc.logn));
}
