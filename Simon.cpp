#include"Test.h"

void Simon128_Encryption(int block_length, int key_length, unsigned char output[], unsigned char input[], unsigned char SeekKey[])
{
	int i,j,l;
	u64 ct[2]={0},pt[2]={0},k[2]={0};
	for(i=0;i<8;i++)
		pt[0]=input[i]+(pt[0]<<8);
	for(i=0;i<8;i++)
		pt[1]=input[i+8]+(pt[1]<<8);
	for(i=0;i<8;i++)
		k[0]=SeekKey[i]+(k[0]<<8);
	for(i=0;i<8;i++)
		k[1]=SeekKey[i+8]+(k[1]<<8);

	int word_size=block_length/2;				//e.t. n
	int key_words=2*key_length/block_length;	//e.t. m
	int roundnum=0;
	int n;	//标记常数类型:j
	int z[5][62]=					//各种常数
	{
			{1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
			{1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
			{1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
			{1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
			{1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}	
	};
switch(key_words+word_size)
{	case(16+4):	roundnum=32; n=0;	break;
	case(24+3): roundnum=36; n=0; 	break;
	case(24+4): roundnum=36; n=1;	break;
	case(32+3):	roundnum=42; n=2;	break;
	case(32+4):	roundnum=44; n=3;	break;
	case(48+2):	roundnum=52; n=2;	break;
	case(48+3):	roundnum=54; n=3;	break;
	case(64+2):	roundnum=68; n=2;	break;
	case(64+3):	roundnum=69; n=3;	break;
	case(64+4):	roundnum=72; n=4;	break;
}
	
	u64 clear=0xffffffffffffffff<<(64-word_size)>>(64-word_size);
	u64 c=clear^0x03;
	u64 key[72],temp;
	for(i=0;i<key_words;i++)			//密钥生成
		key[i]=k[key_words-1-i];
	if(roundnum<62)	
		if(key_words==4)
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=temp^key[i-3];
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)]^c;
			}
		else
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)]^c;
			}
	else
		if(key_words==4)
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=temp^key[i-3];
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)%62]^c;
			}
		else
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)%62]^c;
			}
	
	u64 L=pt[0],R=pt[1];
	for(i=0;i<roundnum;i++)																//加密算法
	{
		temp=L;
		L=(R^( ((L<<1)^(L>>(word_size-1)))&((L<<8)^(L>>(word_size-8))) )^( (L<<2)^(L>>(word_size-2)) )^key[i])&clear;
		R=temp;
	}
	ct[0]=L;
	ct[1]=R;
	for(i=15;i>7;i--)
		output[15-i]=(ct[0]>>(8*(i-8)))&0xff;
	for(i=7;i>=0;i--)
		output[15-i]=(ct[1]>>(8*(i)))&0xff;
}

void Simon128_Decryption(int block_length, int key_length, unsigned char output[], unsigned char input[], unsigned char SeekKey[])
{
	int i,j,l;
	u64 ct[2]={0},pt[2]={0},k[2]={0};
	for(i=0;i<8;i++)
		pt[0]=input[i]+(pt[0]<<8);
	for(i=0;i<8;i++)
		pt[1]=input[i+8]+(pt[1]<<8);
	for(i=0;i<8;i++)
		k[0]=SeekKey[i]+(k[0]<<8);
	for(i=0;i<8;i++)
		k[1]=SeekKey[i+8]+(k[1]<<8);
	int word_size=block_length/2;				//e.t. n
	int key_words=2*key_length/block_length;	//e.t. m
	int roundnum=0;
	int n;	//标记常数类型:j
	int z[5][62]=					//各种常数
	{
			{1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
			{1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
			{1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
			{1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
			{1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}	
	};
switch(key_words+word_size)
{	case(16+4):	roundnum=32; n=0;	break;
	case(24+3): roundnum=36; n=0; 	break;
	case(24+4): roundnum=36; n=1;	break;
	case(32+3):	roundnum=42; n=2;	break;
	case(32+4):	roundnum=44; n=3;	break;
	case(48+2):	roundnum=52; n=2;	break;
	case(48+3):	roundnum=54; n=3;	break;
	case(64+2):	roundnum=68; n=2;	break;
	case(64+3):	roundnum=69; n=3;	break;
	case(64+4):	roundnum=72; n=4;	break;
}
	u64 clear=0xffffffffffffffff<<(64-word_size)>>(64-word_size);
	u64 c=clear^0x03;
	u64 key[72],temp;
	for(i=0;i<key_words;i++)			//密钥生成
		key[i]=k[key_words-1-i];
	if(roundnum<62)	
		if(key_words==4)
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=temp^key[i-3];
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)]^c;
			}
		else
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)]^c;
			}
	else
		if(key_words==4)
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=temp^key[i-3];
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)%62]^c;
			}
		else
			for(;i<roundnum;i++)
			{	temp=((key[i-1]>>3)^(key[i-1]<<(word_size-3)))&clear;
				temp=(temp^(temp>>1)^(temp<<(word_size-1)))&clear;
				key[i]=key[i-key_words]^temp^z[n][(i-key_words)%62]^c;
			}
	
	u64 L=pt[0],R=pt[1];
	for(i=0;i<roundnum;i++)																//加密算法
	{
		temp=R;
		R=(L^( ((R<<1)^(R>>(word_size-1)))&((R<<8)^(R>>(word_size-8))) )^( (R<<2)^(R>>(word_size-2)) )^key[roundnum-1-i])&clear;
		L=temp;
	}
	ct[0]=L;
	ct[1]=R;
	for(i=15;i>7;i--)
		output[15-i]=(ct[0]>>(8*(i-8)))&0xff;
	for(i=7;i>=0;i--)
		output[15-i]=(ct[1]>>(8*(i)))&0xff;
}