#ifndef __RP_RP_VERIFY_H
#define __RP_RP_VERIFY_H

#include "IDP_init.h"
#include "CLIENT_compute.h"

int RP_verify(struct sigma* signature, element_t* m_vector, char* select_vector, \
    struct public_key_IDP* pk_IDP);

#endif