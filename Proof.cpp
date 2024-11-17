#include"POW.h"

void generate_proof(FILE* path, int c, int n, int s, BIGNUM* phi_N, BIGNUM* N, POW_challenge chal, POW_tag* tag, POW_proof* proof, BIGNUM* e) {
	BN_CTX* ctx = BN_CTX_new();
	unsigned char* fileblock_cloud = (unsigned char*)malloc(sizeof(unsigned char) * (POW_BLOCKSIZE));
	char* str_sec = (char*)malloc(sizeof(char) * (POW_SECSIZE));
	unsigned char* hex_sec = (unsigned char*)malloc(sizeof(unsigned char) * (POW_SECSIZE) * 2);
	memset(hex_sec, '\0', (POW_SECSIZE) * 2);

	unsigned char hex_wt[POW_SECSIZE * 2];
	memset(hex_wt, '0', POW_SECSIZE * 2);

	unsigned char* sha_str = (unsigned char*)malloc(sizeof(char) * 20);
	unsigned char* sha_hex = (unsigned char*)malloc(sizeof(unsigned char) * 40);
	memset(sha_str, '\0', sizeof(char) * 20);
	memset(sha_hex, '\0', sizeof(char) * 40);


	BIGNUM* bn_str_sec = BN_new();
	BIGNUM* tao_ij = BN_new();
	BIGNUM* miu_ij = BN_new();
	BIGNUM* sigma_i = BN_new();
	BIGNUM* ktag_i = BN_new();
	BIGNUM* t_tao = BN_new();
	BIGNUM* xhet_hash = BN_new();
	BIGNUM* Index = BN_new();
	
	LARGE_INTEGER frequency;
	LARGE_INTEGER start, end;
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);

	for (int timer = 0; timer < (Timer + Timer1); timer++)
	{
		fseek(path, 0L, SEEK_SET);
		for (int i = 0; i < c; i++)
		{

			memset(sha_str, '\0', sizeof(char) * 20);
			memset(sha_hex, '\0', sizeof(char) * 40);
			SHA_INT(i, sha_str);
			str2Hex_Hash(sha_str, 20, sha_hex);
			sha_hex[39] = '\0';
			BN_hex2bn(&Index, (char*)sha_hex);
			BN_mod(Index, Index, phi_N, ctx);

			memset(fileblock_cloud, '\0', POW_BLOCKSIZE);
			fread(fileblock_cloud, sizeof(unsigned char), POW_BLOCKSIZE, path);
			for (int j = 0; j < GROUP_NUMBER; j++)
			{
				memset(str_sec, '\0', POW_SECSIZE);
				memset(hex_sec, '\0', POW_SECSIZE * 2);
				memcpy(str_sec, &fileblock_cloud[j * POW_SECSIZE], sizeof(unsigned char) * POW_SECSIZE);
				str2Hex(str_sec, POW_SECSIZE, hex_sec);
				BN_hex2bn(&bn_str_sec, (char*)hex_sec);
				BN_mod(bn_str_sec, bn_str_sec, phi_N, ctx);

			
				BN_mod_mul(tao_ij, chal.v[i], bn_str_sec, phi_N, ctx); // tao_ij = v_i * m_ij
				BN_mod_add(proof->Tao_i[i], proof->Tao_i[i], tao_ij, phi_N, ctx);// tao_i = tao_i1+tao_i2+...+tao_is
			
				BN_mod_mul(miu_ij, chal.v[i], bn_str_sec, phi_N, ctx); // miu_ij = v_i * m_ij
				BN_mod_add(proof->Delta_j[j], proof->Delta_j[j], miu_ij, phi_N, ctx);// Delta_1 =m_i1+m_i1+...m_i1
			
				//printf("proof->Tao_i[%d]:%s   proof->Delta_j[%d]:%s\n", i, BN_bn2dec(proof->Tao_i[i]), j, BN_bn2dec(proof->Delta_j[j]));
			}
			BN_mod_exp(sigma_i, tag->sigma[i], chal.v[i], N , ctx); // sigma_i =  sigma_i ^ v_i 
			BN_mod_mul(proof->Sigma, proof->Sigma, sigma_i, N, ctx); // sigma = sigma_1 * sigma_2....

			BN_mod_exp(ktag_i, tag->K_tag[i], chal.v[i], N, ctx); 
			BN_mod_mul(proof->ktag, proof->ktag, ktag_i, N, ctx); 

			BN_mod_mul(tag->x_het[i], tag->x_het[i], chal.v[i], phi_N, ctx);
			BN_mod_add(proof->aggregate_x_het, proof->aggregate_x_het, tag->x_het[i], phi_N, ctx);

		
			BN_mod_mul(tag->y_het[i], tag->y_het[i], chal.v[i], phi_N, ctx);
			BN_mod_add(proof->aggregate_y_het, proof->aggregate_y_het, tag->y_het[i], phi_N, ctx);

			BN_mod_mul(xhet_hash, tag->x_het[i], Index, phi_N, ctx);
			BN_mod_add(proof->Z, proof->Z, xhet_hash, phi_N, ctx);

		}
	}
	QueryPerformanceCounter(&end);
	double elapsedTime = (end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
	printf("%.5f\n", elapsedTime / (Timer + Timer1));
	
	//printf("proof->aggregate_x_het:%s\nproof->aggregate_y_het:%s\n", BN_bn2dec(proof->aggregate_x_het), BN_bn2dec(proof->aggregate_y_het));
	
	BN_free(bn_str_sec);
	BN_free(tao_ij);
	BN_free(miu_ij);
	BN_free(sigma_i);
}

void verify_proof(int c, int s, POW_key* key, POW_challenge chal, POW_proof* proof, POW_tag* tag, BIGNUM* g, BIGNUM* h, BIGNUM* phi_N, BIGNUM* N,  BIGNUM* e) {
	BN_CTX* ctx = BN_CTX_new();

	BIGNUM* pk_j_miu_j = BN_new();
	BIGNUM* pk_mui_all = BN_new();

	BIGNUM* g_pow_x = BN_new();
	BIGNUM* h_pow_y = BN_new();
	BIGNUM* g_pow_mul_h_pow = BN_new();
	BN_one(pk_mui_all);

	unsigned char* sha_hex = (unsigned char*)malloc(sizeof(unsigned char) * 40);
	unsigned char* sha_str = (unsigned char*)malloc(sizeof(unsigned char) * 20);
	memset(sha_str, '\0', sizeof(char) * 20);
	memset(sha_hex, '\0', sizeof(char) * 40);
	BIGNUM* r1 = BN_new();
	BIGNUM* t_i_pow_tao_i = BN_new();
	BIGNUM* pk_pow_tao_i = BN_new();
	BIGNUM* all_pk_pow_tao_i = BN_new();
	BIGNUM* Index = BN_new();
	BN_one(all_pk_pow_tao_i);


	LARGE_INTEGER frequency;
	LARGE_INTEGER start, end;
	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);

	for (int timer = 0; timer < (Timer + Timer1); timer++)
	{

	for (int j = 0; j < GROUP_NUMBER; j++)
	{
		BN_mod_exp(pk_j_miu_j, key->z[j], proof->Delta_j[j],N, ctx);
		BN_mod_mul(pk_mui_all, pk_mui_all, pk_j_miu_j, N, ctx);
	}

	BN_mod_exp(g_pow_x, g, proof->aggregate_x_het,N,ctx);

	BN_mod_exp(h_pow_y, h, proof->aggregate_y_het, N, ctx);

	BN_mod_mul(g_pow_mul_h_pow, g_pow_x, h_pow_y, N,  ctx);

	BN_mod_mul(pk_mui_all, pk_mui_all, g_pow_mul_h_pow, N, ctx);

	int com_r = BN_cmp(proof->Sigma, pk_mui_all);
	//printf("r1:%s \n", BN_bn2dec(proof->Sigma));
	//printf("r2:%s \n", BN_bn2dec(pk_mui_all));
	//if (com_r == 0) {
	//	printf("\nPass!\n");
	//}
	//else if (com_r == 1) {
	//	printf("\nr1 > r2\n");
	//}
	//else if (com_r == -1) {
	//	printf("\nr1< r2\n");
	//}
	//KKKKKKK
	
	}
	QueryPerformanceCounter(&end);
	double elapsedTime = (end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
	printf("%.5f\n", elapsedTime / (Timer + Timer1));


	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);
	for (int timer = 0; timer < (Timer + Timer1); timer++)
	{
	BN_mod_exp(t_i_pow_tao_i, e, proof->Z, N, ctx);

	for (int i = 0; i < c; i++)
	{
		memset(sha_str, '\0', sizeof(char) * 20);
		memset(sha_hex, '\0', sizeof(char) * 40);
		SHA_INT(i, sha_str);
		str2Hex_Hash(sha_str, 20, sha_hex);
		sha_hex[39] = '\0';
		BN_hex2bn(&Index, (char*)sha_hex);
		BN_mod(Index, Index, phi_N, ctx);

		BN_mod_exp(pk_pow_tao_i, tag->t[i], proof->Tao_i[i], N, ctx);
		BN_mod_exp(pk_pow_tao_i, pk_pow_tao_i, Index, N, ctx);
		BN_mod_mul(all_pk_pow_tao_i, all_pk_pow_tao_i, pk_pow_tao_i, N, ctx);
	}
	BN_mod_mul(r1, all_pk_pow_tao_i, t_i_pow_tao_i, N, ctx);

	int com_r = BN_cmp(r1, proof->ktag);

	/*printf("r1:%s \n", BN_bn2dec(r1));
	printf("r2:%s \n", BN_bn2dec(proof->ktag));
	if (com_r == 0) {
		printf("\nPass!\n");
	}
	else if (com_r == 1) {
		printf("\nr1 > r2\n");
	}
	else if (com_r == -1) {
		printf("\nr1< r2\n");
	}*/
	}
	QueryPerformanceCounter(&end);
	elapsedTime = (end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
	printf("%.5f\n", elapsedTime / (Timer + Timer1));

}