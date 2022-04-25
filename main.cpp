#include"Test.h"


unsigned char SimpleSwap(unsigned char S1[],unsigned char S2[])
{
	int i,j,k,l;
	unsigned int word1,word2;
	unsigned char temp[4];
	for(i=0;i<4;i++)
	{
		if  (  (S1[4*i]+(S1[4*i+1]<<4)+(S1[4*i+2]<<8)+(S1[4*i+3]<<12) )!=(  S2[4*i]+(S2[4*i+1]<<4)+(S2[4*i+2]<<8)+(S2[4*i+3]<<12)  )  )
		{
			for(j=0;j<4;j++)
			{
				temp[j]=S1[4*i+j];
				S1[4*i+j]=S2[4*i+j];
				S2[4*i+j]=temp[j];
			}
			return 1;
		}
	}
}

void Print_State(unsigned char S[])
{
	int i,j;
	for(i=0;i<4;i++)
	{
		for(j=0;j<4;j++)
			printf("%x ",S[4*j+i]);
		printf("\n");
	}
	printf("\n");
}

int v(unsigned char a,unsigned char b,unsigned char c,unsigned char d)
{
	int result=0;
	if(a==0) result++;
	if(b==0) result++;
	if(c==0) result++;
	if(d==0) result++;
	return result;
}

int main()
{
	unsigned char Seedkey[32], Direction=1,Subkey[2000]; int KeyLen=128;
	unsigned char input[128];
	int in_len=128; unsigned char output[128];
	int out_len[10]; unsigned char key[128];
	int CryptRound=8;
	int i,j,k,l;
	Make_Sbox_Table();
	//算法验证：
	for(i=0;i<32;i++)
		*(Seedkey+i)=0x5f;
	for(i=0;i<32;i++)
		*(input+i)=0x7f;
	//加密速度测试：
	double c=2,c7=10;
	int time=pow(c,24);
	time_t   begin,end;   
	for(i=0;i<32;i++)
		*(Seedkey+i)=0xff;
	unsigned char Seedkey1[32]={0xfb,0x6a,0x09,0x9e,0xcf,0x31,0x3a,0x7c,0xb0,0x2b,0x50,0x79,0x0e,0x98,0x2e,0xca};
	unsigned char input1[128]={0xe8,0x20,0xcc,0x34,0x07,0xe7,0x35,0x01,0x2b,0xf8,0xcc,0x29,0xbb,0x1a,0xc3,0x8f};
	unsigned char input2[128]={0xcb,0x73,0xf6,0xd1,0x80,0xf0,0x6e,0x1c,0x8b,0xb2,0x22,0x2c,0xa5,0x11,0x12,0x28};
	in_len=128;KeyLen=128;

	for(i=0;i<32;i++)
		*(Seedkey+i)=0x5f;
	for(i=0;i<32;i++)
		*(input+i)=0x7f;
	/*printf("\nEncryption end(%d)\n",Spring_Encryption(input,in_len, output, out_len, Seedkey, KeyLen));
	for(i=0;i<in_len>>3;i++)
		printf("%x,",*(output+i));printf("\n");*/
	unsigned int cnt1=0,cnt2=0,WrongPair=0;
	unsigned char c0[128],c1[128],p0[128],p1[128],p[16];


	//apply AES distinguisher on Spring block cipher   
	printf("Apply 6-round AES distinguisher on Spring block cipher\n");   
	for(cnt1=0x1;cnt1<pow(c,13);cnt1++)
	{
		for(i=0;i<16;i++)
		input2[i]=input1[i];
		for(i=0;i<4;i++)
			input1[i]=input1[i]^(cnt1>>(4*i) );			//构造 wt(v(p0^p1))=3
		WrongPair=0;
		for(cnt2=0;cnt2<pow(c,11);cnt2++)
		{
			Spring_Encryption(input1,in_len, c0, out_len, Seedkey1, KeyLen);
			Spring_Encryption(input2,in_len, c1, out_len, Seedkey1, KeyLen);
			SimpleSwap(c0,c1);
			Spring_Decryption(c0,in_len, p0, out_len, Seedkey1, KeyLen);
			Spring_Decryption(c1,in_len, p1, out_len, Seedkey1, KeyLen);
			SimpleSwap(p0,p1);
			for(i=0;i<16;i++)
				p[i]=p0[i]^p1[i];
			for(i=0;i<4;i++)
			{ 
				if(v(p[4*i],p[4*i+1],p[4*i+2],p[4*i+3])>=2)
				WrongPair=1;		
				break;	}
			if(WrongPair) {printf("P0:\n");Print_State(p0);printf("P1:\n");Print_State(p1);printf("delta:\n");Print_State(p); break;}			
			for(i=0;i<16;i++)
			{
				input1[i]=p0[i];
				input2[i]=p1[i];
			}
		}
		if(WrongPair) break;
	}
	if(WrongPair)
		printf("cnt1=%d\n,cnt2=%d\n This cipher is 6-round AES\n",cnt1,cnt2);
	else
		printf("This cipher is not AES\n");


	//apply AES distinguisher on Midori128 block cipher   
	printf("\nApply 6-round AES distinguisher on Midori128 block cipher\n");   
	for(cnt1=0x1;cnt1<pow(c,13);cnt1++)
	{
		for(i=0;i<16;i++)
		input2[i]=input1[i];
		for(i=0;i<4;i++)
			input1[i]=input1[i]^(cnt1>>(4*i) );			//构造 wt(v(p0^p1))=3
		WrongPair=0;
	//	Print_State(input1);
	//	Print_State(input2);
		for(cnt2=0;cnt2<pow(c,11);cnt2++)
		{
			Midori128_Encryption(input1,in_len, c0, 128, Seedkey1, KeyLen);
			Midori128_Encryption(input2,in_len, c1, 128, Seedkey1, KeyLen);
			SimpleSwap(c0,c1);
			Midori128_Decryption(c0,in_len, p0, 128, Seedkey1, KeyLen);
			Midori128_Decryption(c1,in_len, p1, 128, Seedkey1, KeyLen);
			SimpleSwap(p0,p1);
			for(i=0;i<16;i++)
				p[i]=p0[i]^p1[i];
			for(i=0;i<4;i++)
			{ 
				if(v(p[4*i],p[4*i+1],p[4*i+2],p[4*i+3])>=2)
				WrongPair=1;		
				break;	}
			if(WrongPair) {printf("P0:\n");Print_State(p0);printf("P1:\n");Print_State(p1);printf("delta:\n");Print_State(p); break;}			
			for(i=0;i<16;i++)
			{
				input1[i]=p0[i];
				input2[i]=p1[i];
			}
		}
		if(WrongPair) break;
	}
	if(WrongPair)
		printf("cnt1=%d\n,cnt2=%d\n This cipher i s 6-round AES\n",cnt1,cnt2);
	else
		printf("This cipher is not 6-round AES\n");
	

	//apply AES distinguisher on Simon128 block cipher   
	printf("\nApply 6-round AES distinguisher on Simon128 block cipher\n");   
/*	unsigned char PP[16]={0x63,0x73,0x65,0x64,0x20,0x73,0x72,0x65,0x6c,0x6c,0x65,0x76,0x61,0x72,0x74,0x20 },
		KK[16]={0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00 };
	Simon128_Encryption(128,128,c0,PP,KK);
	for(i=0;i<16;i++)
		printf("%2x,  ", c0[i]);
	printf("\n");
	Simon128_Decryption(128,128,PP,c0,KK);
	for(i=0;i<16;i++)
		printf("%2x,  ", PP[i]);*/
	for(cnt1=0x1;cnt1<pow(c,13);cnt1++)
	{
		for(i=0;i<16;i++)
		input2[i]=input1[i];
		for(i=0;i<4;i++)
			input1[i]=input1[i]^(cnt1>>(4*i) );			//构造 wt(v(p0^p1))=3
		WrongPair=0;
		for(cnt2=0;cnt2<pow(c,11);cnt2++)
		{
			Simon128_Encryption(128,128,c0,input1,Seedkey1);
			Simon128_Encryption(128,128,c1,input2,Seedkey1);
			SimpleSwap(c0,c1);
			Simon128_Decryption(128,128,p0,c0,Seedkey1);
			Simon128_Decryption(128,128,p1,c1,Seedkey1);
			SimpleSwap(p0,p1);
			for(i=0;i<16;i++)
				p[i]=p0[i]^p1[i];
			for(i=0;i<4;i++)
			{ 
				if(v(p[4*i],p[4*i+1],p[4*i+2],p[4*i+3])>=2)
				WrongPair=1;		
				break;	}
			if(WrongPair) {printf("P0:\n");Print_State(p0);printf("P1:\n");Print_State(p1);printf("delta:\n");Print_State(p); break;}			
			for(i=0;i<16;i++)
			{
				input1[i]=p0[i];
				input2[i]=p1[i];
			}
		}
		if(WrongPair) break;
	}
	if(WrongPair)
		printf("cnt1=%d\n,cnt2=%d\n This cipher is 6-round AES\n",cnt1,cnt2);
	else
		printf("This cipher is not 6-round AES\n");

	//apply AES distinguisher on full AES
	printf("\nApply 6-round AES distinguisher on full AES\n");   
	unsigned char inputt[16]={0x66,0xE9,0x4B,0xD4,0xEF,0x8A,0x2C,0x3B,0x88,0x4C,0xFA,0x59,0xCA,0x34,0x2B,0x2E};
	unsigned char keyt[16]={0};
	/*AES(inputt,128,c0,128,keyt,128);
	Print_State(c0);
	AES_Inv(c0,128,p0,128,keyt,128);
	Print_State(p0);*/
	for(cnt1=0x1;cnt1<pow(c,13);cnt1++)
	{
		for(i=0;i<16;i++)
		input2[i]=input1[i];
		for(i=0;i<4;i++)
			input1[i]=input1[i]^(cnt1>>(4*i) );			//构造 wt(v(p0^p1))=3
		WrongPair=0;
		for(cnt2=0;cnt2<pow(c,11);cnt2++)
		{
			AES_Encryption(input1,128,c0,128,Seedkey1,128);
			AES_Encryption(input2,128,c1,128,Seedkey1,128);
			SimpleSwap(c0,c1);
			AES_Decryption(c0,128,p0,128,Seedkey1,128);
			AES_Decryption(c1,128,p1,128,Seedkey1,128);
			SimpleSwap(p0,p1);
			for(i=0;i<16;i++)
				p[i]=p0[i]^p1[i];
			for(i=0;i<4;i++)
			{ 
				if(v(p[4*i],p[4*i+1],p[4*i+2],p[4*i+3])>=2)
				WrongPair=1;		
				break;	}
			if(WrongPair) {printf("P0:\n");Print_State(p0);printf("P1:\n");Print_State(p1);printf("delta:\n");Print_State(p); break;}			
			for(i=0;i<16;i++)
			{
				input1[i]=p0[i];
				input2[i]=p1[i];
			}
		}
		if(WrongPair) break;
	}
	if(WrongPair)
		printf("cnt1=%d\n,cnt2=%d\n This cipher is 6-round AES\n",cnt1,cnt2);
	else
		printf("This cipher is not 6-round AES\n");

	return 0;
}