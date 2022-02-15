element_t r;
element_t r_plus;
element_t res;
element_t parcel;

element_t r_x;
element_t r_r;
element_t r_alpha;
element_t r_beta;
element_t* r_var 

element_t R1;element_init_G1(R1, *pk_IDP->pair);
element_t R2;element_init_G1(R2, *pk_IDP->pair);

element_t* r_var = (element_t*)malloc(N*sizeof(element_t));
for(int i=0; i<N; i++) {
        if(is_hidden(select_vector, i)) {
            element_init_Zr(r_var[i], *pk_IDP->pair);
            element_random(r_var[i]);
        }
    }


free(pair_use);
free(sk_IDP);
free(pk_IDP);
free(m_vector);
free(select_vector);
free(sigma_c_user);
free(signature);