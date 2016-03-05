/*
 * cRFCadd.h
 *
 *  Created on: 2015年9月24日
 *      Author: 10177270
 */

#ifndef CPP_CRFC_H_
#define CPP_CRFC_H_

#include "RFC.h"

/****************** structure ************************/
struct CompressEqID
{
	unsigned short ComId;
	CompressEqID *nextComId;
};


struct CompressComponent
{
	//string
	unsigned int nBitStraing;   //nBitStraing=ncells /32
	unsigned int *BitStraing;

	//array
	unsigned int nArray; // 1的数目
	CompressEqID *ComIdHead;
	CompressEqID *ComIdTear;
};




/****************** function declaration ************************/
void BitMapCompress(struct PNODER *tmpPnoder, struct CompressComponent *tmpCompressBitMap);
unsigned int cRFCTransIndx2eqID(unsigned int index,struct CompressComponent *tmpCompressBitMap);
void CountMemory_CRFC();
void Lookup_package_cRFC_6F();
void cRFC_6F();





#endif /* CPP_BRP_CRFC_6F_EXP_SRC_CRFC_H_ */
