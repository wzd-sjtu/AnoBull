#ifndef __TEST_TEST_H
#define __TEST_TEST_H

#include "/usr/local/include/pbc/pbc.h"
#include "/usr/local/include/pbc/pbc_test.h"
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <openssl/sha.h>
#include "all_def.h"
#include "basic_algorithm.h"
#include "Elliptic_Curve.h"


int verify_sigma_c_equation_1(struct sigma_c* sigma_c_specific, struct public_key_IDP* pk_IDP);

#endif