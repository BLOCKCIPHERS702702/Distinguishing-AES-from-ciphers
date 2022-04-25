#include"Test.h"
//#define byte8 unsigned char
//#define word32 unsigned int
int Block_size=128;
int Nr = (Block_size>>4)+12;// Midori迭代轮数
int Nk = 4;// 密钥32位字大小
byte8 state[16];// 4×4状态矩阵
byte8 RoundKey[320];

byte8 Sb0[16] = { 0xc, 0xa,  0xd,  0x3,  0xe,  0xb, 0xf,  0x7,  0x8,  0x9,  0x1, 0x5, 0x0, 0x2, 0x4, 0x6}; 
byte8 Sb1[16] = { 0x1 ,  0x0 ,  0x5 ,  0x3 ,  0xe ,  0x2 ,  0xf ,  0x7 ,  0xd ,  0xa ,  0x9 ,  0xb ,  0xc ,  0x8 ,  0x4 ,  0x6};

unsigned char rsbox[256];

byte8 SSb(byte8 input,int num)
{
	int i,j,k;
	int p[4][8]={{4,1,6,3,0,5,2,7},{1,6,7,0,5,2,3,4},{2,3,4,1,6,7,0,5},{7,4,1,2,3,0,5,6}},inv_p[8];
	for(i=0;i<8;i++)
		inv_p[p[num][i]]=i;
	byte8 s[8],a=0,b;
	for(i=0;i<8;i++)
		s[i]=( input>>(7-p[num][i]) )&0x01;
	for(i=0;i<8;i++)
		a=(a<<1)+s[i];
	b=Sb1[a&0xf];
	a=Sb1[a>>4];
	a=(a<<4)+b;
	for(i=0;i<8;i++)
		s[i]=(a>>(7-inv_p[i]) )&0x01;
	a=0;
	for(i=0;i<8;i++)
		a=(a<<1)+s[i];
	return a;
}
void InvShuﬄeCell()
 {
	 int p[16]={0,7,14,9,5,2,11,12,15,8,1,6,10,13,4,3},i;
	 byte8 s[16];
	 for(i=0;i<16;i++)
		s[i] =state[i];
	 for(i=0;i<16;i++)
		state[i] =s[p[i]];
 }
 void MixColumn()
 {
	 int i,j,k;
	 byte8 s[16],sum;
	 for(i=0;i<16;i++)
		 s[i]=state[i];
	 for(i=0;i<4;i++)
	{
		sum=s[4*i]^s[4*i+1]^s[4*i+2]^s[4*i+3];
		for(j=0;j<4;j++)
			 state[4*i+j]=sum^s[4*i+j];
	 }
 }
void Key_Schedule(byte8 SeedKey[], byte8 Direction, byte8 Subkey[])//Direction 0加密，Direction1解密
{
	byte8  Rcon[20][16] = { 
	{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,1, 0,1,0,1, 1,0,1,1, 0,0,1,1 },{0,1,1,1 ,1,0,0,0 ,1,1,0,0, 0,0,0,0},{1,0,1,0, 0,1,0,0, 0,0,1,1 ,0,1,0,1}
,{0,1,1,0, 0,0,1,0, 0,0,0,1, 0,0,1,1},{0,0,0,1, 0,0,0,0, 0,1,0,0, 1,1,1,1},{1,1,0,1, 0,0,0,1, 0,1,1,1, 0,0,0,0}
,{0,0,0,0, 0,0,1,0, 0,1,1,0, 0,1,1,0},{0,0,0,0, 1,0,1,1, 1,1,0,0, 1,1,0,0},{1,0,0,1, 0,1,0,0, 1,0,0,0, 0,0,0,1}
,{0,1,0,0, 0,0,0,0, 1,0,1,1, 1,0,0,0},{0,1,1,1, 0,0,0,1, 1,0,0,1, 0,1,1,1},{0,0,1,0, 0,0,1,0, 1,0,0,0, 1,1,1,0}
,{0,1,0,1, 0,0,0,1, 0,0,1,1, 0,0,0,0},{1,1,1,1, 1,0,0,0, 1,1,0,0, 1,0,1,0},{1,1,0,1, 1,1,1,1, 1,0,0,1, 0,0,0,0}
,{0,1,1,1, 1,1,0,0, 1,0,0,0, 0,0,0,1},{0,0,0,1, 1,1,0,0, 0,0,1,0, 0,1,0,0},{0,0,1,0, 0,0,1,1, 1,0,1,1, 0,1,0,0}
,{0,1,1,0, 0,0,1,0, 1,0,0,0, 1,0,1,0}
}; 
	int i,j;
	byte8 K[2][16];
	if(!Direction)
	{
	for(i=0;i<20;i++)
		for(j=0;j<16;j++)
			Subkey[j+16*i]=Rcon[i][j]^SeedKey[j];
	}
	if(Direction)
	{
		for(i=1;i<Nr;i++)
		{
			for(j=0;j<16;j++)
				state[j]=Rcon[i][j]^SeedKey[j];
			MixColumn();
			InvShuﬄeCell();
			for(j=0;j<16;j++)
				Subkey[j+16*i]=state[j];
		}
	}
}
void SubCell_128()
{
	int i,j,k;
	for(i=0;i<16;i++)
			state[i]=SSb(state[i],(i&0x3));
}
 void ShuﬄeCell()
 {
	 int p[16]={0,10,5,15,14,4,11,1,9,3,12,6,7,13,2,8},i;
	 byte8 s[16];
	 for(i=0;i<16;i++)
		s[i] =state[i];
	 for(i=0;i<16;i++)
		state[i] =s[p[i]];
 }
 void KeyAdd(int round)
 {
	 int i;
	 for(i=0;i<16;i++)
		 state[i]=state[i]^RoundKey[i+16*round];
 }
 void Midori128_Encryption(byte8 input[],int in_len, byte8 output[],int out_len, byte8 key[], int keylen)
 {
	 int i,j,round = 0;
	Key_Schedule( key,0,RoundKey);
	for(i=0;i<16;i++)
	{	state[i]=input[i];
	}
	KeyAdd(0);
	for(i=1;i<20;i++)
	{
		SubCell_128();
		ShuﬄeCell();
		MixColumn();
		KeyAdd(i);
	}
	SubCell_128();
	KeyAdd(0);
	for(i=0;i<16;i++)
		output[i]=state[i];
 }
 void Midori128_Decryption(byte8 input[],int in_len, byte8 output[],int out_len, byte8 key[], int keylen)
 {
	 int i,j,round = 0;
	Key_Schedule( key,1,RoundKey);
	for(i=0;i<16;i++)
	{	state[i]=input[i];
	}
	KeyAdd(0);
	for(i=1;i<Nr;i++)
	{
		SubCell_128();
		MixColumn();
		InvShuﬄeCell();
		KeyAdd(Nr-i);
	}
	SubCell_128();
	KeyAdd(0);
	for(i=0;i<16;i++)
		output[i]=state[i];
 }



