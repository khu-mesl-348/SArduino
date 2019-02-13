#include "crc16.h"

void gen_crc_table()
{
	#ifndef USE_CRC_TABLE
	register unsigned short	i, j;
	register unsigned short	crc_accum;

	/* 0 ~ 255 ������ CRC�� �̸� ��� */
	/* ex) i=2 �̸� 0x020000 �� polynomial�� CRC ������ �ϴ� ���� */
	for(i=0; i<256; i++)
	{
		crc_accum = ((unsigned short)i<<8);
		/* CRC�������� �����ϵ��� 8-bit shift */
		for(j=0; j<8; j++)
		{
			/* ���������� MSB�� 1���� �˻� */
			if(crc_accum & 0x8000L)
				crc_accum = (crc_accum << 1) ^ POLYNOMIAL;
				/* ���̸� 1-bit shift�ϰ� polynomial�� ����(==XOR) */
			else
				crc_accum = (crc_accum << 1);
				/* �����̸� 1-bit shift�� ��*/
		}
		/* ��������� �� 16-bit�� shift �Ǿ��� */
		/* �������� ���� �� */
		crc_table[i] = crc_accum;

		//printf("%03d=%04x, ", i, crc_accum);
		//if(i%7 == 0)
		//	printf("\n");
	}
	#endif
	return;
}


/*
������ ����� CRC ���� �߰��� �����Ϳ� ���� ������
����:      ___________
      8005 | XX 00 00
                yy yy ---> CRC

����:      ______________
      8005 | XX ZZ 00 00
                yy yy 00
                   ww ww ---> CRC'
*/
unsigned short update_crc(unsigned short crc_accum, unsigned char *data_blk_ptr,unsigned short data_blk_size)
{
	register unsigned short i, j;

	for(j=0; j<data_blk_size; j++)
	{
		/* �߰��� ������ ZZ��                      */
		/* ���� ���� ���������� ���� ����Ʈ��    */
		/* �ڸ����� �����Ƿ� �� ���� ���ϰ� �ٽ�   */
		/* �� �ڸ������� �������� ����             */
		i = ((unsigned short)(crc_accum >> 8) ^ *data_blk_ptr++) & 0xff;
		crc_accum = (crc_accum << 8) ^ crc_table[i];
        /* ���������� ���� ����Ʈ�� �ڿ� 0x00 ��   */
		/* �߰��Ǿ� �ڸ����� �ö󰡰� ���ڸ���     */
        /* �������� ������ */
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
