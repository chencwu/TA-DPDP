#include"POW.h"

char value2HexCh(const int value) {
	char res = '\0';
	if (value >= 0 && value <= 9) {
		res = (char)(value)+48;
	}
	else if (value >= 10 && value <= 15) {
		res = (char)(value - 10 + 65);
	}
	else {
		printf("value err\n");
	}
	return res;
}

void str2Hex(const char* str_in, int length, unsigned char* str_out) {
	int high = 0;
	int low = 0;
	const char* tmp_in = str_in;
	int i, j;
	for (i = 0, j = 0; j < length; j++) {
		high = ((unsigned int)*tmp_in & 0xf0) >> 4;//from char to int
		low = (unsigned int)*tmp_in & 0x0f;
		str_out[i] = value2HexCh(high);//from int to hex
		str_out[i + 1] = value2HexCh(low);
		tmp_in += 1;
		i += 2;
	}
	str_out[i] = '\0';
}

void str2Hex_Hash(const unsigned char* str_in, int length, unsigned char* str_out) {
	int high = 0;
	int low = 0;
	const unsigned char* tmp_in = str_in;

	int i, j;
	for (i = 0, j = 0; j < length; j++) {
		high = ((unsigned int)*tmp_in & 0xf0) >> 4;//from char to int
		low = (unsigned int)*tmp_in & 0x0f;
		str_out[i] = value2HexCh(high);//from int to hex
		str_out[i + 1] = value2HexCh(low);
		tmp_in += 1;
		i += 2;
	}
	str_out[i] = '\0';
}

int hexCh2value(const char ch) {
	int res = 0;
	if (ch >= '0' && ch <= '9') {
		res = (int)(ch - '0');
	}
	else
		res = (int)(ch - 'A') + 10;
	return res;
	
}

void hex2Str(char* hex, unsigned char* str) {
	int high, low;
	int tmp = 0;
	while (*hex) {
		high = hexCh2value(*hex);
		hex++;
		low = hexCh2value(*hex);
		tmp = (high << 4) + low;
		*str++ = (char)tmp;
		hex++;

	}
}

void printHex(const unsigned char* pBuf, int nLen)
{
	for (int i = 0; i < nLen; ++i)
	{
		printf("%02x", pBuf[i]);
	}
	printf("\n");
}

void SHA_INT(int i, unsigned char* sha_str) {
	unsigned char* sha_current_str1 = (unsigned char*)malloc(sizeof(unsigned char) * 20);
	char* sha_current_str = (char*)malloc(sizeof(char) * 20);
	memset(sha_current_str, '\0', 20);
	sprintf(sha_current_str, "%d", i);
	//printf(" %s \n", sha_current_str);
	memcpy(sha_current_str1, sha_current_str, sizeof(char) * 20);
	unsigned char* ret = SHA1(sha_current_str1, sizeof(sha_current_str1), sha_str);
	//printHex(sha_str, 20);
}

int String2Int(unsigned char* str) {
	long res = 0;
	while (*str >= 48 && *str <= 57)//如果是数字才进行转换，数字0~9的ASCII码：48~57 
	{
		res = 10 * res + *str++ - 48;//字符'0'的ASCII码为48,48-48=0刚好转化为数字0 
	}
	return (int)res;
}
