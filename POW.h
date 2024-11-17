#define _CRT_SECURE_NO_WARNINGS 1

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include<time.h>
#include <windows.h>
#include <cassert>	
#include<vector>
#include<iostream>
#include <time.h>
#include <pthread.h>

using namespace std;


#define POW_BLOCKSIZE 2048 // 4KB each block
#define GROUP_NUMBER  8   //16B each sector

#define POW_SECSIZE (POW_BLOCKSIZE/GROUP_NUMBER)     //16B each sector

#define CHALLENGE_BLOCK 460

//正常验证情况下 Timer=1 Timer1=0
#define Timer 10
#define Timer1 20


typedef struct POW_key_struct POW_key;//keypair = (x,y,z_i)
struct POW_key_struct {
	int u;
	BIGNUM** x;//a_j
	BIGNUM** y;//a_k
	BIGNUM** z;
};

typedef struct POW_tag_struct POW_tag;//keypair = (x,y,z_i)
struct POW_tag_struct {
	BIGNUM** sigma;//
	BIGNUM** K_tag;//
	BIGNUM** x_het;
	BIGNUM** y_het;
	BIGNUM* e;
	BIGNUM** t;
};

typedef struct POW_challenge_struct POW_challenge;//challenge = (i,v_i)
struct POW_challenge_struct {
	int* index;//i
	BIGNUM** v;//v_i
};

typedef struct POW_proof_struct POW_proof;//proof = {Delta_j,Tao_i,Sigma}

struct POW_proof_struct {
	BIGNUM** Tao_i;//
	BIGNUM** Delta_j;
	BIGNUM* Sigma;
	BIGNUM* ktag;
	BIGNUM* aggregate_x_het;
	BIGNUM* aggregate_y_het;
	BIGNUM* Z;

};



void setup_key(BIGNUM* phi_N, BIGNUM* N, BIGNUM* g, BIGNUM* h, POW_key* key);
void pow_tag_block(FILE* path, BIGNUM* phi_N, BIGNUM* N, BIGNUM* g, BIGNUM* h, POW_key* sk, int s, int n, POW_tag* tag,  BIGNUM* e);
void generate_challenge(int blocknum, POW_challenge* chal, BIGNUM* phi_N, BIGNUM* N);
void generate_proof(FILE* path, int c, int n, int s, BIGNUM* phi_N, BIGNUM* N, POW_challenge chal, POW_tag* tag, POW_proof* proof, BIGNUM* e);
void verify_proof(int c, int s, POW_key* key, POW_challenge chal, POW_proof* proof, POW_tag* tag, BIGNUM* g, BIGNUM* h, BIGNUM* phi_N, BIGNUM* N, BIGNUM* e);

//Type Turn
char value2HexCh(const int value);
void str2Hex(const char* str_in, int length, unsigned char* str_out);
void str2Hex_Hash(const unsigned char* str_in, int length, unsigned char* str_out);
int hexCh2value(const char ch);
void hex2Str(char* hex, unsigned char* str);
void SHA_INT(int i, unsigned char* sha_str);
void printHex(const unsigned char* pBuf, int nLen);
int String2Int(unsigned char* str);