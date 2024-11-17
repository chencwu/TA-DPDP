#include"POW.h"

//void printHex(const unsigned char* pBuf, int nLen)
//{
//    for (int i = 0; i < nLen; ++i)
//    {
//        printf("%02x", pBuf[i]);
//    }
//    printf("\n");
//}
//int main() {
//    char* sha_current_str = (char*)malloc(sizeof(char) * 20);
//    char sText[] = "2";
//    int i;
//    for ( i = 0; i < 9; i++)
//    {
//        sprintf(sha_current_str, "%d", i);
//        printf(" %s \n", sha_current_str);
//        unsigned char sSHA[20] = { 0 };
//        //unsigned char sSHA2[20] = { 0 };
//        unsigned char* ret = SHA1((const unsigned char*)sha_current_str, strlen(sha_current_str), sSHA);
//        //unsigned char* ret2 = SHA1((const unsigned char*)sha_current_str, strlen(sha_current_str), sSHA2);
//        printf("ret %p \n", ret);
//        printf("sSHA %p \n", sSHA);
//        //printf("ret2 %p \n", ret2);
//        //printf("sSHA2 %p \n", sSHA2);
//        printHex(sSHA, 20);
//    }
//    /*memset(sha_current_str, '\0', POW_SECSIZE * 2);*/
//    sprintf(sha_current_str, "%d", i-1);
//    printf(" %s \n", sha_current_str);
//    unsigned char sSHA[20] = { 0 };
//    //unsigned char sSHA2[20] = { 0 };
//    unsigned char* ret = SHA1((const unsigned char*)sha_current_str, strlen(sha_current_str), sSHA);
//    //unsigned char* ret2 = SHA1((const unsigned char*)sha_current_str, strlen(sha_current_str), sSHA2);
//    printf("ret %p \n", ret);
//    printf("sSHA %p \n", sSHA);
//    //printf("ret2 %p \n", ret2);
//    //printf("sSHA2 %p \n", sSHA2);
//    printHex(sSHA, 20);
//    //printHex(sSHA2, 20);
//
//
//	return 0;
//}