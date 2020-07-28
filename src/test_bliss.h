#ifndef _TEST_BLISS_H_
#define _TEST_BLISS_H_

#ifdef __cplusplus
extern "C" {
#endif

enum bliss_param_set_id_t {
        BLISS_I =     1,
        BLISS_II =    2,
        BLISS_III =   3,
        BLISS_IV =    4,
        BLISS_B_I =   5,
        BLISS_B_II =  6,
        BLISS_B_III = 7,
        BLISS_B_IV =  8
};
  
void test_bliss(unsigned int);
  
#ifdef __cplusplus
}
#endif


#endif
