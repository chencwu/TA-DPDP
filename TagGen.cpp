#include"POW.h"
void pow_tag_block(FILE* path, BIGNUM* phi_N, BIGNUM* N, BIGNUM* g, BIGNUM* h, POW_key* sk, int s, int n, POW_tag* tag, BIGNUM* e) {
	BN_CTX* ctx = BN_CTX_new();

	unsigned char* fileblock = (unsigned char*)malloc(sizeof(unsigned char) * (POW_BLOCKSIZE)); // read a file block each time
	char* str_current_sec = (char*)malloc(sizeof(char) * (POW_SECSIZE)); // store sector in string manner
	unsigned char* hex_current_sec = (unsigned char*)malloc(sizeof(unsigned char) * (POW_SECSIZE) * 2);// store sector in hex manner
	unsigned char* sha_str = (unsigned char*)malloc(sizeof(unsigned char) * 20);
	unsigned char* sha_current_str1 = (unsigned char*)malloc(sizeof(unsigned char) * 20);
	char* sha_current_str = (char*)malloc(sizeof(char) * 20);
	unsigned char* sha_hex = (unsigned char*)malloc(sizeof(unsigned char) * 40);
	unsigned char* index_i_k = (unsigned char*)malloc(sizeof(int) * 2);

	BIGNUM* bn_current_sec = BN_new();
	BIGNUM* sig_ki = BN_new();
	BIGNUM* delta_i = BN_new();
	BIGNUM* bn_index = BN_new();
	memset(sha_str, '\0', sizeof(char) * 20);
	memset(sha_hex, '\0', sizeof(char) * 40);

	BIGNUM* Index = BN_new();
	BN_copy(tag->e, e);
	LARGE_INTEGER frequency;
	LARGE_INTEGER start, end;

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);
	for (int timer = 0; timer < (Timer + Timer1); timer++)
	{
		fseek(path, 0L, SEEK_SET);
		for (int i = 0; i < n; i++)
		{

			memset(fileblock, '\0', POW_BLOCKSIZE);
			fread(fileblock, sizeof(unsigned char), POW_BLOCKSIZE, path);

			BN_one(tag->sigma[i]);// set sigma_i be 0 intially

			for (int j = 1; j < GROUP_NUMBER; j++)
			{
				memset(str_current_sec, '\0', POW_SECSIZE);
				memset(hex_current_sec, '\0', POW_SECSIZE * 2);
				memcpy(str_current_sec, &fileblock[j * POW_SECSIZE], sizeof(unsigned char) * POW_SECSIZE);
				str2Hex(str_current_sec, POW_SECSIZE, hex_current_sec);
				BN_hex2bn(&bn_current_sec, (char*)hex_current_sec);
				BN_mod(bn_current_sec, bn_current_sec, phi_N, ctx);

				BN_mod_exp(sig_ki, sk->z[j], bn_current_sec, N, ctx);
				BN_mod_mul(tag->sigma[i], tag->sigma[i], sig_ki, N, ctx);
			}

		}
	}
	QueryPerformanceCounter(&end);
	double elapsedTime = (end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
	printf("%.5f\n", elapsedTime / (Timer + Timer1));
	//x_het y_het  K[i]
	BIGNUM* r_x = BN_new();
	BIGNUM* r_y = BN_new();
	BIGNUM* g_x = BN_new();
	BIGNUM* h_y = BN_new();
	BIGNUM* x_m = BN_new();
	BIGNUM* y_m = BN_new();
	BIGNUM* r_xy = BN_new();
	BIGNUM* zero = BN_new();
	BIGNUM* t = BN_new();
	BIGNUM* t_mij = BN_new();
	BIGNUM* e_rx = BN_new();

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);
	for (int timer = 0; timer < (Timer + Timer1); timer++)
	{
		BN_zero(zero);
		fseek(path, 0L, SEEK_SET);
		for (int i = 0; i < n; i++)
		{
			memset(sha_str, '\0', sizeof(char) * 20);
			memset(sha_hex, '\0', sizeof(char) * 40);
			SHA_INT(i, sha_str);
			str2Hex_Hash(sha_str, 20, sha_hex);
			sha_hex[39] = '\0';
			BN_hex2bn(&Index, (char*)sha_hex);
			BN_mod(Index, Index, phi_N, ctx);



			memset(fileblock, '\0', POW_BLOCKSIZE);
			fread(fileblock, sizeof(unsigned char), POW_BLOCKSIZE, path);

			BN_rand(r_x, POW_SECSIZE * 8, NULL, NULL);
			BN_rand(r_y, POW_SECSIZE * 8, NULL, NULL);

			BN_mod(r_x, r_x, phi_N, ctx);
			BN_mod(r_y, r_y, phi_N, ctx);

			//BN_mod_mul(r_x, r_x, Index, phi_N, ctx);

			BN_mod_exp(g_x, g, r_x, N, ctx);
			BN_mod_exp(h_y, h, r_y, N, ctx);

			BN_mod_mul(r_xy, g_x, h_y, N, ctx);
			BN_mod_mul(tag->sigma[i], tag->sigma[i], r_xy, N, ctx);

			BN_mod_exp(t, e, sk->x[0], N, ctx);//t=e^x
			BN_copy(tag->t[i], t);

			BN_mod_exp(e_rx, e, r_x, N, ctx);//t=e^rx

			BN_zero(t_mij);
			for (int j = 0; j < GROUP_NUMBER; j++)
			{

				memset(str_current_sec, '\0', POW_SECSIZE);
				memset(hex_current_sec, '\0', POW_SECSIZE * 2);
				memcpy(str_current_sec, &fileblock[j * POW_SECSIZE], sizeof(unsigned char) * POW_SECSIZE);
				str2Hex(str_current_sec, POW_SECSIZE, hex_current_sec);
				BN_hex2bn(&bn_current_sec, (char*)hex_current_sec);
				BN_mod(bn_current_sec, bn_current_sec, phi_N, ctx);
				//printf("bn_str_sec:%s \n", BN_bn2dec(bn_current_sec));
				if (j == 0) {
					BN_mod_mul(x_m, sk->x[0], bn_current_sec, phi_N, ctx);//x*m_ipai
					BN_mod_sub(tag->x_het[i], r_x, x_m, phi_N, ctx);//x_het=rx-x*m_ipai
					BN_mod_mul(y_m, sk->y[0], bn_current_sec, phi_N, ctx);//y*m_ipai
					BN_mod_sub(tag->y_het[i], r_y, y_m, phi_N, ctx);//x_het=ry-y*m_ipai
				}
				else BN_mod_add(t_mij, t_mij, bn_current_sec, phi_N, ctx);
			}

			BN_mod_exp(tag->K_tag[i], t, t_mij, N, ctx);
			BN_mod_mul(tag->K_tag[i], tag->K_tag[i], e_rx, N, ctx);
			BN_mod_exp(tag->K_tag[i], tag->K_tag[i], Index, N, ctx);
		}
	}
	QueryPerformanceCounter(&end);
	elapsedTime = (end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
	printf("%.5f\n", elapsedTime / (Timer + Timer1));
	BN_free(bn_current_sec);
	BN_free(sig_ki);
	BN_free(delta_i);
	BN_free(bn_index);
	BN_free(r_x);
	BN_free(r_y);
	BN_free(g_x);
	BN_free(h_y);
	BN_free(x_m);
	BN_free(y_m);
}