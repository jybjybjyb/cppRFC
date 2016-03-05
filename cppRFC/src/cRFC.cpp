/*
 * Compress.cpp
 *
 *  Created on: 2015年9月24日
 *      Author: 10177270
*/

#if 1

//#include "stdafx.h"
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <windows.h>
#include "RFC.h"

using namespace std;


void
BitMapCompress(struct PNODER *tmpPnoder, struct CompressComponent *tmpComponent){

	//init
	unsigned int pos;
	unsigned int k;
	unsigned int mask;

	tmpComponent->nBitStraing  = (tmpPnoder->ncells/32) + 1;
	unsigned short *pcell;
	pcell=tmpPnoder->cell;


	//init BitStraing
	tmpComponent->BitStraing =(unsigned int *)malloc(tmpComponent->nBitStraing * sizeof(unsigned int));
	if(NULL == tmpComponent->BitStraing){
		printf("malloc CompressBitMap->BitStraing faild ...\n");
		exit(1);
	}
	tmpComponent->BitStraing[0]=1;

	//init Array
	tmpComponent->ComIdHead =(CompressEqID *)malloc(sizeof(CompressEqID));
	if(NULL == tmpComponent->ComIdHead){
		printf("malloc tmpCompressBitMap->ComIdHead faild ...\n");
		exit(1);
	}

	tmpComponent->ComIdTear=tmpComponent->ComIdHead;
	tmpComponent->ComIdTear->ComId=tmpPnoder->cell[0];
	tmpComponent->ComIdTear->nextComId=NULL;

	tmpComponent->nArray=1;


	//map cell[n] to string & array
	for(unsigned int n=1; n<tmpPnoder->ncells;n++){
		pos = n % 32;
		k = n / 32;
		mask=1;
		mask=mask<<pos;
		if(pcell[n]==pcell[n-1]){
			//相等置 0
			mask= ~mask;
			tmpComponent->BitStraing[k] &= mask;
		}else{
			//不相等置 1
			tmpComponent->BitStraing[k] |= mask;

			tmpComponent->ComIdTear->nextComId = (CompressEqID *) malloc(sizeof(CompressEqID));
			if(NULL == tmpComponent->ComIdTear->nextComId){
				printf("malloc faild ...\n");
				exit(1);
			}

			tmpComponent->ComIdTear = tmpComponent->ComIdTear->nextComId;
			tmpComponent->ComIdTear->nextComId = NULL;
			tmpComponent->ComIdTear->ComId=pcell[n];
			tmpComponent->nArray++;
		}
	}

}

void cRFC_6F(){

	struct PNODER tmpP1;
	struct PNODER *ptmpP1;
	ptmpP1=&tmpP1;
	struct PNODE *ptmpP0;

	//set CompressComponent
	for(unsigned int j=0;j<DIM; j++){
		/*trace phase0*/
		ptmpP0=&phase0_Nodes[j];

		ptmpP1->ncells=65536;
		//malloc cell
		ptmpP1->cell=(unsigned short *)malloc(65536 * sizeof(unsigned short));
		if(NULL == ptmpP1->cell){
			printf("(malloc) error !!!\n");
			exit(1);
		}

		memcpy(ptmpP1->cell,ptmpP0->cell,65536 * sizeof(unsigned short));
		memcpy(&ptmpP1->listEqs,&ptmpP0->listEqs, sizeof(struct LISTEqS));

		BitMapCompress(ptmpP1, &CompressBitMap_p0[j]);
	}

	for(unsigned int k=0;k<2; k++){
		/*trace phase1*/
		BitMapCompress(&phase1_Nodes[k], &CompressBitMap_p1[k]);
	}
}



unsigned int
cRFCTransIndx2eqID(unsigned int index,struct CompressComponent *tmpCompressBitMap){

	//init
	unsigned int eqID;
	unsigned int pos;
	unsigned int k;
	unsigned int mask;

	unsigned int cnt_1=0;
	unsigned int i;
	i=index;
	struct CompressEqID *ptmpComId;
	ptmpComId=tmpCompressBitMap->ComIdHead;

	while(i!=0){
		pos = i % 32;
		k = i / 32;
		mask=1;
		mask=mask<<pos;

		if( (tmpCompressBitMap->BitStraing[k] & mask) != 0){
			cnt_1++;
		}
		i--;
	}

	for(unsigned int j=0;j<cnt_1;j++){
		ptmpComId=ptmpComId->nextComId;
		if(tmpCompressBitMap == NULL){
			printf("tmpCompressBitMap == NULL");
			exit(1);
		}
	}

	eqID=ptmpComId->ComId;
	return eqID;
}



void
Lookup_package_cRFC_6F() {
	//init
	ReadPackFile();
//	InitResults();

	unsigned int cid[8]; //6+2
	unsigned int indx[3]; //2+1
	unsigned int tmpResult;
	struct PACKAGE * pTmpPack;


	/*look up every single rule*/
	for (unsigned int line = 0; line < g_packageset.numPackages; line++){


		/*	phase 0 */
		for (unsigned int i = 0; i < DIM; i++) {
			cid[i]=cRFCTransIndx2eqID((unsigned int)pTmpPack->dim[i], &CompressBitMap_p0[i]);
		}

		/*	phase 1 */
		indx[0] = cid[dot[0]] * (unsigned int)phase0_Nodes[dot[1]].listEqs.nCES * (unsigned int)phase0_Nodes[dot[2]].listEqs.nCES \
				+ cid[dot[1]] * (unsigned int)phase0_Nodes[dot[2]].listEqs.nCES \
				+ cid[dot[2]];
		indx[1] = cid[dot[3]] * (unsigned int)phase0_Nodes[dot[4]].listEqs.nCES * (unsigned int)phase0_Nodes[dot[5]].listEqs.nCES \
				+ cid[dot[4]] * (unsigned int)phase0_Nodes[dot[5]].listEqs.nCES \
				+ cid[dot[5]];

/*		if((indx[0] > tmpPart->phase1_Nodes[0].ncells) || (indx[1] > tmpPart->phase1_Nodes[1].ncells)){
			printf("\nlookup indx_phase1 overflow!!\n");
//			exit(1);
		}*/

		cid[6]=cRFCTransIndx2eqID(indx[0], &CompressBitMap_p1[0]);
		cid[7]=cRFCTransIndx2eqID(indx[1], &CompressBitMap_p1[1]);

//		cid[6] = (unsigned int)tmpPart->phase1_Nodes[0].cell[indx[0]];
//		cid[7] = (unsigned int)tmpPart->phase1_Nodes[1].cell[indx[1]];

		/* phase 2 */
		indx[2] = cid[6] * phase1_Nodes[1].listEqs.nCES + cid[7];

/*		if((indx[2] > tmpPart->phase1_Nodes[2].ncells) ){
			printf("\nlookup indx_phase2 overflow!!\n");
			exit(1);
		}*/
		// store lookup result into lookupResult[]
		tmpResult = (unsigned int)phase2_Node.cell[indx[2]];

		//next rule
		pTmpPack=pTmpPack->pNextPack;

		//storing result
		LookupResult[line]=tmpResult;

	}	//end of line
}


void CountMemory_CRFC() {

	printf("\n__________________________ BRP CRFC 6F _________________________\n");

	unsigned int single_p0_cellused;
	unsigned int single_p1_cellused;
	unsigned int single_p2_cellused;
//	unsigned int tot_p0_cellused=0;
//	unsigned int tot_p1_cellused=0;
//	unsigned int tot_p2_cellused=0;
//	unsigned int tot=0;
	unsigned int numbits,single_tot;

	numbits = sizeof(unsigned short);


	single_tot=0;
	single_p0_cellused=0;
	single_p1_cellused=0;
	single_p2_cellused=0;

	for(unsigned int j =0; j<DIM;j++){
		single_p0_cellused += CompressBitMap_p0[j].nBitStraing *sizeof(unsigned int)+\
				CompressBitMap_p0[j].nArray* numbits;

	}

	for(unsigned int k =0; k<2;k++){
		single_p1_cellused += CompressBitMap_p1[k].nBitStraing *sizeof(unsigned int)+\
				CompressBitMap_p1[k].nArray* numbits;
	}

/*		single_p2_cellused += ptmpPart->CompressBitMap_p2.nBitStraing *sizeof(unsigned int)+\
			ptmpPart->CompressBitMap_p2.nArray* numbits;*/
	single_p2_cellused += phase2_Node.ncells* numbits;

	single_tot+=single_p0_cellused;
	single_tot+=single_p1_cellused;
	single_tot+=single_p2_cellused;


	printf("\n____totally____");
	printf("\n%-12s%-12s%-12s \n","phase0","phase1","phase2");
	printf("%-12d%-12d%-12d [Bytes] \n", single_p0_cellused,single_p1_cellused,single_p2_cellused );

	printf("\nMemory Used Totally: %d Bytes\n", single_tot);

	/*
	unsigned int n_node;
	unsigned int node_size;

	n_node=28;
	node_size=sizeof(struct TreeNode);
	printf("\nTree used: %d Bytes\n", n_node*node_size);*/

	FILE *fp;
	char filename[] = "cRFC_memorycost.txt";
	fp = fopen(filename, "w+");
	if (fp == NULL) {
		printf("Cannot open memoryused file \n");
		exit(1);
	}

	fprintf(fp,"\n______________CRFC_________________________\n");
	fprintf(fp,"\n%-12s%-12s%-12s \n","phase0","phase1","phase2");
	fprintf(fp,"%-12d%-12d%-12d [Bytes] \n", single_p0_cellused,single_p1_cellused,single_p2_cellused );

	fprintf(fp,"\nMemory Used Totally: %d Bytes\n", single_tot);



	fclose(fp);




}
#endif
