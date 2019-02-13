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