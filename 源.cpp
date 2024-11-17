#pragma warning
#pragma comment(lib, "pthreadVC2.lib")
/*******************************************************************
 *
 *^^^^^^^^^^^^^^^^^^^^^^^^^^^^佛祖保佑^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *
 *                             _ooOoo_
 *                            o8888888o
 *                            88" . "88
 *                            (| -_- |)
 *                            O\  =  /O
 *                         ____/`---'\____
 *                       .'  \\|     |//  `.
 *                      /  \\|||  :  |||//  \
 *                     /  _||||| -:- |||||-  \
 *                     |   | \\\  -  /// |   |
 *                     | \_|  ''\---/''  |   |
 *                     \  .-\__  `-`  ___/-. /
 *                   ___`. .'  /--.--\  `. .'__
 *                ."" '<  `.___\_wcc_/___.'  >'"".
 *               | | :  `- \`.;`\ _ /`;.`/ - ` : | |
 *               \  \ `-.   \_ __\ /__ _/   .-` /  /
 *          ======'-.____`-.___\_____/___.-`____.-'======
 *                             '=---='
 *          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 *^^^^^^^^^^^^^^^^^^^^^码到成功^^^^^^^论文顺利^^^^^^^^^^^^^^^^^^^^^^
 *
 *******************************************************************/
#include "pow.h"
extern "C" {
#include <openssl/applink.c>
}

double time_compress = 0;
double time_extract = 0;
double time_all = 0;
double nukonw_number = 0;
int cishu = 5;
int chusu = cishu;
double compress_time = 0;
double time_watermarking = 0;


int main() {
	const char* filename = "C:\\Users\\cc\\Desktop\\paper\\05MB_file.txt";//	1MB_file
	FILE* path = fopen(filename, "rb"); // read file in binary mode
	fseek(path, 0L, SEEK_END);// locate end of file

	int size = ftell(path);// return offset of file end and compute the file size
	int n = size / POW_BLOCKSIZE;     //number of block in a page
	int s = POW_BLOCKSIZE / POW_SECSIZE;      //total number of sectors in a message block
	printf("%d\nthe file  have %d block and each block is %d sectors\n", size, n,s);

	BN_CTX* ctx;
	ctx = BN_CTX_new();

	BIGNUM* g = BN_new();
	BIGNUM* h = BN_new();
	BIGNUM* p = BN_new();
	BIGNUM* q = BN_new();
	BIGNUM* pp = BN_new();
	BIGNUM* qq = BN_new();
	BIGNUM* N = BN_new();
	BIGNUM* phi_N = BN_new();
	BIGNUM* one = BN_new();

	BN_one(one);
	BN_sub(pp, p, one);
	int init_i, init_j, init_u;
	BN_one(one);
	BN_generate_prime(p, 128, NULL, NULL, NULL, NULL, NULL);
	BN_generate_prime(q, 128, NULL, NULL, NULL, NULL, NULL);
	BN_generate_prime(g, 128, NULL, NULL, NULL, NULL, NULL);
	BN_generate_prime(h, 128, NULL, NULL, NULL, NULL, NULL);

	BN_mul(N, p, q, ctx);//n=p*q->256-bit
	BN_sub(pp, p, one);//pp=p-1
	BN_sub(qq, q, one);//qq=q-1
	BN_mul(phi_N, pp, qq, ctx);


	unsigned char* sha_hex = (unsigned char*)malloc(sizeof(unsigned char) * 40);
	unsigned char* sha_str = (unsigned char*)malloc(sizeof(unsigned char) * 20);
	memset(sha_str, '\0', sizeof(char) * 20);
	memset(sha_hex, '\0', sizeof(char) * 40);
	int event = 123456;
	BIGNUM* e = BN_new();
	SHA_INT(event, sha_str);
	str2Hex_Hash(sha_str, 20, sha_hex);
	sha_hex[39] = '\0';
	BN_hex2bn(&e, (char*)sha_hex);
	BN_mod(e, e, phi_N, ctx);


	printf("----------------------Phase -1: initialize system success!----------------------\n");


	POW_key* c_key = (POW_key*)malloc(sizeof(POW_key));
	c_key->x = (BIGNUM**)malloc(sizeof(BIGNUM*) * GROUP_NUMBER);
	c_key->y = (BIGNUM**)malloc(sizeof(BIGNUM*) * GROUP_NUMBER);
	c_key->z = (BIGNUM**)malloc(sizeof(BIGNUM*) * GROUP_NUMBER);

	for (init_u = 0; init_u < GROUP_NUMBER; init_u++)
	{
		c_key->u = init_u;
		c_key->x[init_u] = BN_new();
		c_key->y[init_u] = BN_new();
		c_key->z[init_u] = BN_new();
	}

	setup_key(phi_N, N, g, h, c_key);
	printf("----------------------Phase 0: initialize key pairs success!----------------------\n");
	

	POW_tag* c_tag = (POW_tag*)malloc(sizeof(POW_tag));
	c_tag->sigma = (BIGNUM**)malloc(sizeof(BIGNUM*) * n);
	c_tag->K_tag = (BIGNUM**)malloc(sizeof(BIGNUM*) * n);
	c_tag->x_het = (BIGNUM**)malloc(sizeof(BIGNUM*) * n);
	c_tag->y_het = (BIGNUM**)malloc(sizeof(BIGNUM*) * n);
	c_tag->t = (BIGNUM**)malloc(sizeof(BIGNUM*) * n);
	c_tag->e = BN_new();

	for (init_i = 0; init_i < n; init_i++)
	{
		c_tag->sigma[init_i] = BN_new();
		c_tag->K_tag[init_i] = BN_new();
		c_tag->x_het[init_i] = BN_new();
		c_tag->y_het[init_i] = BN_new();
		c_tag->t[init_i] = BN_new();
	}
	
	path = fopen(filename, "rb");
	pow_tag_block(path, phi_N, N,g, h, c_key, s, n, c_tag,e);
	printf("\n----------------------Phase 1: generate initial PoW tag success!----------------------\n");


	
	int c = 0;
	if (n < 460) {
		c = n;
	}
	else
		c = 460;
	POW_challenge chal;
	chal.index = (int*)malloc(sizeof(int) * c);
	chal.v = (BIGNUM**)malloc(sizeof(BIGNUM*) * c);
	generate_challenge(c, &chal, phi_N,N);
	printf("\n----------------------Phase 2: generate initial PoW chal success!----------------------\n");

	POW_proof* proof = (POW_proof*)malloc(sizeof(POW_proof));
	proof->Delta_j= (BIGNUM**)malloc(sizeof(BIGNUM*) * s);
	proof->Tao_i = (BIGNUM**)malloc(sizeof(BIGNUM*) * c);
	proof->aggregate_x_het = BN_new();
	proof->aggregate_y_het = BN_new();
	BN_zero(proof->aggregate_x_het);
	BN_zero(proof->aggregate_y_het);
	proof->Sigma = BN_new();
	proof->Z = BN_new();
	proof->ktag = BN_new();
	BN_one(proof->Sigma);
	BN_one(proof->ktag);
	for (init_j = 0; init_j < s; init_j++)
	{
		proof->Delta_j[init_j] = BN_new();
	}
	for (init_i = 0; init_i < c; init_i++)
	{
		proof->Tao_i[init_i] = BN_new();
	
	}
	generate_proof(path,c,n,s, phi_N, N,chal,c_tag ,proof,e);
	printf("\n----------------------Phase 3: generate initial PoW proof success!----------------------\n");
	
	verify_proof(c, s, c_key,chal,proof,c_tag,g,h, phi_N, N,e);
	printf("\n----------------------Phase 4: generate initial PoW verify success!----------------------\n");
	

	return 0;

}