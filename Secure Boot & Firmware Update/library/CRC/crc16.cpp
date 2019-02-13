#include "crc16.h"

void gen_crc_table()
{
	#ifndef USE_CRC_TABLE
	register unsigned short	i, j;
	register unsigned short	crc_accum;

	/* 0 ~ 255 까지의 CRC를 미리 계산 */
	/* ex) i=2 이면 0x020000 을 polynomial로 CRC 나눗셈 하는 것임 */
	for(i=0; i<256; i++)
	{
		crc_accum = ((unsigned short)i<<8);
		/* CRC나눗셈이 가능하도록 8-bit shift */
		for(j=0; j<8; j++)
		{
			/* 나머지항의 MSB가 1인지 검사 */
			if(crc_accum & 0x8000L)
				crc_accum = (crc_accum << 1) ^ POLYNOMIAL;
				/* 참이면 1-bit shift하고 polynomial을 빼줌(==XOR) */
			else
				crc_accum = (crc_accum << 1);
				/* 거짓이면 1-bit shift만 함*/
		}
		/* 결과적으로 총 16-bit가 shift 되었고 */
		/* 나머지만 남게 됨 */
		crc_table[i] = crc_accum;

		//printf("%03d=%04x, ", i, crc_accum);
		//if(i%7 == 0)
		//	printf("\n");
	}
	#endif
	return;
}


/*
이전에 계산한 CRC 값을 추가된 데이터에 맞춰 갱신함
이전:      ___________
      8005 | XX 00 00
                yy yy ---> CRC

갱신:      ______________
      8005 | XX ZZ 00 00
                yy yy 00
                   ww ww ---> CRC'
*/
unsigned short update_crc(unsigned short crc_accum, unsigned char *data_blk_ptr,unsigned short data_blk_size)
{
	register unsigned short i, j;

	for(j=0; j<data_blk_size; j++)
	{
		/* 추가된 데이터 ZZ는                      */
		/* 이전 계산시 나머지항의 상위 바이트와    */
		/* 자리수가 맞으므로 그 둘을 합하고 다시   */
		/* 그 자리까지의 나머지를 구함             */
		i = ((unsigned short)(crc_accum >> 8) ^ *data_blk_ptr++) & 0xff;
		crc_accum = (crc_accum << 8) ^ crc_table[i];
        /* 나머지항의 하위 바이트는 뒤에 0x00 이   */
		/* 추가되어 자리수가 올라가고 앞자리의     */
        /* 나머지와 더해짐 */
	}
	return crc_accum;
}

/*=========================================================================
 < verifyCRC16 >
 : check CRC code based on hash value in arr. If crc code is invalid,
   the result of update_crc is not zero.
			unsigned char* arr = VP data set received from Firmware Update
			return = the result of CRC check
					check == 0 : valid data
					check != 0 : invalid data
==========================================================================*/

unsigned short verifyCRC16(unsigned char* arr) {
	unsigned char verifyBuf[34];
	unsigned short crc, check;

	gen_crc_table();

	crc = (short)(((short)arr[45]) << 8) | arr[46];
	for (int i = 0; i < 32; i++)
		verifyBuf[i] = arr[i + 2];

	verifyBuf[32] = (crc & 0xFF00) >> 8;
	verifyBuf[33] = (crc & 0x00FF);

	check = update_crc(0, verifyBuf, 34);

	return check;
}
