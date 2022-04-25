#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<math.h>
#include<iostream>   
#include<time.h>
  #include<ctime>   
#include <memory.h>
  using   namespace   std;   
  typedef unsigned int word32;
typedef unsigned char byte8;
typedef unsigned long long u64;
typedef unsigned int u32;
int Spring_Encryption(unsigned char *input,int in_len, unsigned char  
*output, int *out_len, unsigned char *key , int keylen);
void Make_Sbox_Table();
int Spring_Decryption(unsigned char *input,int in_len, unsigned char 
*output,int *out_len, unsigned char *key, int keylen);
void Midori128_Encryption(byte8 input[],int in_len, byte8 output[],int out_len, byte8 key[], int keylen);
void Midori128_Decryption(byte8 input[],int in_len, byte8 output[],int out_len, byte8 key[], int keylen);
void Simon128_Encryption(int block_length, int key_length, unsigned char output[], unsigned char input[], unsigned char Key[]);
void Simon128_Decryption(int block_length, int key_length, unsigned char output[], unsigned char input[], unsigned char Key[]);
void AES_Encryption(byte8 input[],int in_len, byte8 output[],int out_len, byte8 key[], int keylen);
void AES_Decryption(byte8 input[],int in_len, byte8 output[],int out_len, byte8 key[], int keylen);

