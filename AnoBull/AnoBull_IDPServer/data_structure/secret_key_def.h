#ifndef __SECRETE_KEY_DEF
#define __SECRETE_KEY_DEF

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>

struct secret_key_IDP {
    // Z_p
    element_t gamma;
};


#endif