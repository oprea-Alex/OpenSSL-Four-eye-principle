#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>


#pragma comment (lib,"ws2_32.lib")
#pragma comment (lib,"crypt32")

FILE _iob[] = { *stdin, *stdout, *stderr };
extern "C" FILE * __cdecl __iob_func(void) { return _iob; }


#define MAX_UINT 4294967295
#define AES_BLOCK_SIZE 16


static int _read_from_file(const char *filename, unsigned char **data, unsigned int *len)
{
	if (data == NULL || len == NULL)
		return 0;

	FILE *fp = fopen(filename, "rb");
	if (fp == NULL)
		return 0;

	fseek(fp, 0, SEEK_END);
	*len = (unsigned int)ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*data = (unsigned char *)malloc(*len);

	fread(*data, 1, *len, fp);
	fclose(fp);

	return 1;
}

static int _write_to_file(const char *filename, unsigned char *data, unsigned int len)
{
	if (data == NULL)
		return 0;

	FILE *fp = fopen(filename, "wb");
	if (fp == NULL)
		return 0;

	fwrite(data, 1, len, fp);

	fclose(fp);

	return 1;
}








void main() {

	unsigned long long k1 = 15350283796570290237; //ei-th roots for Ci(cubic root in this case because both public eponents e1 = e2 = 3)
	unsigned long long k2 = 8284334661900246245;

	unsigned long long k = k1 ^ k2; //get 64 bytes aes key k 


	//after XOR, k gets stored on 64 bytes ull integer
	//but need to pass k to SHA256 as a string
	BIGNUM* k_hex = BN_new();
	BIGNUM* max = BN_new();
	BIGNUM* factor = BN_new();
	BN_set_word(k_hex, 0);
	BN_set_word(max, MAX_UINT); //MAX_UINT = 2^32 - 1 -- maximum value possible stored on unsigned int(4 bytes)
	BN_CTX* BNctx = BN_CTX_new();
	
	unsigned int aux = (unsigned int)(k / MAX_UINT);
	BN_set_word(factor, aux); //getting the no of MAX_UINT in k
	BN_mul(k_hex, max, factor, BNctx); //store it in BIGNUM k_hex

	unsigned int last = k % MAX_UINT;
	BN_set_word(factor, last);
	BN_add(k_hex, factor, k_hex);//adding the remainder (< MAX_UINT) to BIGNUM k_hex

	unsigned char* XOR_hex = (unsigned char*)malloc(sizeof(unsigned char*) * sizeof(unsigned long long));
	aux = BN_bn2bin(k_hex,XOR_hex);//conversion from ull integer to hex string through BN pre-implemented bn2bin
	_write_to_file("xor.out", XOR_hex, 8);
	BN_CTX_free(BNctx);


	///SHA256(XOR_hex)
	//to get the AES key
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, XOR_hex, 8);

	unsigned char* md = (unsigned char*)malloc(sizeof(unsigned char*) * SHA256_DIGEST_LENGTH);
	SHA256_Final(md,&ctx);

	_write_to_file("md.out", md, SHA256_DIGEST_LENGTH);
	//Print the digest as one long hex value
	printf("0x");
	for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", md[i]);
	putchar('\n');


	///AES 256 EBC Decrypt
	//using SHA256's md as key and no IV

	unsigned char* plaintext = (unsigned char*) malloc(sizeof(unsigned char*) * AES_BLOCK_SIZE);
	unsigned int len_plaintext = 0;
	int len = 0;
	unsigned char* ciphertext = NULL;
	unsigned int len_ciphertext = 0;
	_read_from_file("cipher.aes", &ciphertext, &len_ciphertext);//cipher.aes file copied in advance from blob using Hxd hex editor  
																//to avoid the need of ASCII -> HEX conversion

	EVP_CIPHER_CTX* sctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_set_padding(sctx, EVP_PADDING_PKCS7);

	EVP_DecryptInit_ex(sctx, EVP_aes_256_ecb(), NULL, md, NULL);
	
	EVP_DecryptUpdate(sctx, plaintext, &len, ciphertext, len_ciphertext);
	len_plaintext += len;
	
	EVP_DecryptFinal_ex(sctx, plaintext + len, &len);
	len_plaintext += len;


	_write_to_file("decrypted.out", plaintext, len_plaintext);



	EVP_CIPHER_CTX_free(sctx);
	free(XOR_hex);
	free(md);
	free(plaintext);
	free(ciphertext);


	printf("\n\nFinal!\n\n");
	getchar();
}