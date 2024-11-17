#include"POW.h"

void setup_key(BIGNUM* phi_N,BIGNUM* N, BIGNUM* g, BIGNUM* h, POW_key* key) {
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* g_pow_x = BN_new();
	BIGNUM* h_pow_y = BN_new();
	BIGNUM* inverse = BN_new();		
	for (int j = 0; j < GROUP_NUMBER; j++)
	{
		BN_rand(key->x[j], 128, 0, 0);
		BN_mod(key->x[j], key->x[j], phi_N, ctx);
		BN_mod_exp(g_pow_x, g, key->x[j], N, ctx);

		BN_rand(key->y[j], 128, 0, 0);
		BN_mod(key->y[j], key->y[j], phi_N, ctx);
		BN_mod_exp(h_pow_y, h, key->y[j], N, ctx);
		BN_mod_inverse(inverse, h_pow_y, N, ctx);// inverse_s = S ^ -1
		BN_mod_mul(key->z[j], g_pow_x, h_pow_y, N, ctx);	
	}
	BN_free(g_pow_x);
	BN_free(h_pow_y);
	BN_CTX_free(ctx);
}

void generate_challenge(int blocknum, POW_challenge* chal, BIGNUM* phi_N, BIGNUM* N) {
	BN_CTX* ctx = BN_CTX_new();//
	for (int i = 0; i < blocknum; i++) {
		chal->index[i] = i;//i
		chal->v[i] = BN_new();//i
		BN_rand(chal->v[i], POW_SECSIZE*8 , 0, 0);//v_i
		BN_mod(chal->v[i], chal->v[i], phi_N, ctx);
		//BN_set_word(chal->v[i],2);
		//BN_one(chal->v[i]);
		//printf("v[%d]:%s \n", i, BN_bn2dec(chal->v[i]));
	}
}



