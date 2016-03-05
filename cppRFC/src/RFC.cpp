/*
 * RFC.cpp	algorithm for Packet Classification

 *
 */


//#include "stdafx.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <windows.h>
#include "GlobalVer.h"
#include "RFC.h"
#include "cRFC.h"

using namespace std;

/* *** function for reading ip range ***
 call form: ReadIPRange(fp,tempfilt->highSIPrange,tempfilt->lowSIPrange)
 fp: pointer to Filters File
 highSIPrange: pointer to the high SIP range in the FILTER structure
 lowSIPrange: pointer to the low SIP range in the FILTER structure
 return: void*/
void ReadIPRange(FILE *fp, unsigned int* highRange, unsigned int* lowRange) {
	/*assumes IPv4 prefixes*/
	// temporary variables to store IP range
	unsigned int trange[4];
	unsigned int mask;
	char validslash;

	// read IP range described by IP/mask
//	fscanf(fp, "%d.%d.%d.%d/%d", &trange[0],&trange[1],&trange[2],&trange[3],&mask);
	fscanf(fp, "%d.%d.%d.%d", &trange[0], &trange[1], &trange[2], &trange[3]);
	fscanf(fp, "%c", &validslash);

	// deal with default mask
	if (validslash != '/')
		mask = 32;
	else
		fscanf(fp, "%d", &mask);

	int masklit1;
	unsigned int masklit2, masklit3;
	mask = 32 - mask;
	masklit1 = mask / 8;
	masklit2 = mask % 8;

	unsigned int ptrange[4];
	int i;
	for (i = 0; i < 4; i++)
		ptrange[i] = trange[i];

	// count the start IP
	for (i = 3; i > 3 - masklit1; i--)
		ptrange[i] = 0;
	if (masklit2 != 0) {
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		masklit3 = ~masklit3;
		ptrange[3 - masklit1] &= masklit3;
	}
	// store start IP
	highRange[0] = ptrange[0];
	highRange[0] <<= 8;
	highRange[0] += ptrange[1];
	lowRange[0] = ptrange[2];
	lowRange[0] <<= 8;
	lowRange[0] += ptrange[3];

	// count the end IP
	for (i = 3; i > 3 - masklit1; i--)
		ptrange[i] = 255;
	if (masklit2 != 0) {
		masklit3 = 1;
		masklit3 <<= masklit2;
		masklit3 -= 1;
		ptrange[3 - masklit1] |= masklit3;
	}
	// store end IP
	highRange[1] = ptrange[0];
	highRange[1] <<= 8;
	highRange[1] += ptrange[1];
	lowRange[1] = ptrange[2];
	lowRange[1] <<= 8;
	lowRange[1] += ptrange[3];
}

/* Read protocol, called by ReadFilter
 fp: pointer to filter set file
 protocol: 17 for tcp
 return: void*/
void ReadProtocol(FILE *fp, unsigned char *from, unsigned char *to) {
	unsigned int tfrom, tto;

	fscanf(fp, "%d : %d", &tfrom, &tto);
	*from = (unsigned char) tfrom;
	*to = (unsigned char) tto;
}

/* Read port, called by ReadFilter
 fp: pointer to filter set file
 from:to	=>	0:65535 : specify the port range
 return: void*/
void ReadPort(FILE *fp, unsigned int *from, unsigned int *to) {
	unsigned int tfrom;
	unsigned int tto;

	fscanf(fp, "%d : %d", &tfrom, &tto);

	*from = tfrom;
	*to = tto;
}

/* Read port, called by ReadFilter
 fp: pointer to filter set file
 from:to	=>	0:65535 : specify the port range
 return: void*/
void ReadAct(FILE *fp, unsigned char *action) {
	unsigned int tAction;

	fscanf(fp, "%d", &tAction);

	*action = (unsigned char)tAction;
}


/* ***	function for loading filters   ***
 fp:		file pointer to filterset file
 filtset: pointer to filterset, global variable
 cost:	the cost(position) of the current filter
 cost就是line的排序
 return:	0, this value can be an error code...*/
int
ReadFilter(FILE *fp, struct FILTSET * filtset, unsigned int cost) {
	char validfilter; // validfilter means an '@'
	struct FILTER *ptempfilt, tempfilt;
	ptempfilt = &tempfilt;

	while (!feof(fp)) {
		fscanf(fp, "%c", &validfilter);
		if (validfilter != '@') {
			continue;	// each rule should begin with an '@'
		}

		for(unsigned int i=0; i<6;i++){
			fscanf(fp, "%d:%d", &ptempfilt->dim[i][0], &ptempfilt->dim[i][1]);
		}

		// copy the temp filter to the global one
		memcpy(&(filtset->filtArr[filtset->numFilters]), ptempfilt,
				sizeof(struct FILTER));

		filtset->numFilters++;

		return SUCCESS;
	} //ending while, rule set 文件逐行读取并转换成filter形式

	return FALSE;
}



/* ***	function for loading filters   ***
 fp:		file pointer to filterset file
 filtset: pointer to filterset, global variable
 cost:	the cost(position) of the current filter
 cost就是line的排序
 return:	0, this value can be an error code...*/
int ReadFilter_bak(FILE *fp, struct FILTSET * filtset, unsigned int cost) {
	/*allocate a few more bytes just to be on the safe side to avoid overflow etc*/
	char validfilter; // validfilter means an '@'
	struct FILTER *tempfilt, tempfilt1;

	//printf("Enter ReadFilter\n");
	while (!feof(fp)) {
		fscanf(fp, "%c", &validfilter);
		if (validfilter != '@')
			continue;	// each rule should begin with an '@'

		tempfilt = &tempfilt1;

		/* 此处的dim[com][]由ReadIPRange根据掩码自动设置
		 *
		 * 16+16+16+16 bit
		 *  */
		ReadIPRange(fp, tempfilt->dim[0], tempfilt->dim[1]);	// reading SIP range
		ReadIPRange(fp, tempfilt->dim[2], tempfilt->dim[3]);	// reading DIP range

		/* DstPort 16bit
		 * SrcPort 16bit
		 * Protocol 8bit
		 * 16+16 bit
		 *  */
		ReadPort(fp, &(tempfilt->dim[4][0]), &(tempfilt->dim[4][1])); //reading SPort range
		ReadPort(fp, &(tempfilt->dim[5][0]), &(tempfilt->dim[5][1])); //reading DPort range

		//ReadProtocol(fp, unsigned char *from, unsigned char *to);


		/*
		 * Action 8bit
		 * */
//		ReadAct(fp, &(tempfilt->act));



		// read the cost (position) , which is specified by the last parameter of this function
		tempfilt->cost = cost;



		// copy the temp filter to the global one
		memcpy(&(filtset->filtArr[filtset->numFilters]), tempfilt, sizeof(struct FILTER));

		filtset->numFilters++;

		//Printf
		#ifdef DEBUG_READRULEs
		printf("\n__________________________rule(%d)_________________________\n",tempfilt->cost+1);
		printf("%-9s%-9s%-9s%-9s%-9s%-9s\n","SIP_h","SIP_l","DIP_h","DIP_l","sPort","dPort");
		printf("%-9d%-9d%-9d%-9d%-9d%-9d\n",\
				tempfilt->dim[0][0],tempfilt->dim[1][0],\
				tempfilt->dim[2][0],tempfilt->dim[3][0],\
				tempfilt->dim[4][0],tempfilt->dim[5][0]);
		printf("%-9d%-9d%-9d%-9d%-9d%-9d\n",\
				tempfilt->dim[0][1],tempfilt->dim[1][1],\
				tempfilt->dim[2][1],tempfilt->dim[3][1],\
				tempfilt->dim[4][1],tempfilt->dim[5][1]);

		//printf("line(cost) is %d\n",tempfilt->cost);
		#endif

		return SUCCESS;
	} //ending while, rule set 文件逐行读取并转换成filter形式

	return FALSE;
}

/* ***	function for loading filters   ***
 fp:		file pointer to filterset file
 filtset: pointer to filterset, global variable
 return:	void*/
void LoadFilters(FILE *fp, struct FILTSET * filtset) {

	filtset->numFilters = 0;	// initial filter number
//	printf("Reading filters..................\n");
	int line = 0;	// the line to read, indeed, this is the cost(position) of the filter to read
	while (!feof(fp)) {
		ReadFilter(fp, filtset, line);
		line++;
	}
//	printf("......................Reading FilterSet finished......................\n");
}




/* Load Filters from file, called by main
 return: void*/
void ReadFilterFile() {
	FILE *fp;	// filter set file pointer
	char filename[] = "filter.txt";
	fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("Couldnt open filter set file \n");
		exit(1);
	}
	printf("........ Filter File %s Loading  ........ \n", filename);

	LoadFilters(fp, &g_filtset);	// loading filters...
	fclose(fp);
	printf("Filters Read %d Rules\n", g_filtset.numFilters);

	// check whether bmp[SIZE] is long enough to provide one bit for each rule
	if (LENGTH * SIZE < g_filtset.numFilters) {
		printf(
				"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\nThe bmp[SIZE] is not long enougth, please set SIZE higher!!!\n");
		exit(1);
	}

}


// Load Package Set into memory
void
LoadPackages(FILE *fp, struct PACKAGESET *packageset) {
	packageset->numPackages = 0;	// initial package number
	char validfilter;				// validfilter means an '@'
	struct PACKAGE * ptemppack;

	while (!feof(fp)) {
		fscanf(fp, "%c", &validfilter);

		if (validfilter != '@'){
			continue;	// each rule should begin with an '@'
			}

		// malloc
		ptemppack=(struct PACKAGE *)malloc(sizeof(struct PACKAGE));
		if(NULL == ptemppack){
			printf("(malloc) load pack error !!!\n");
			exit(1);
		}

		for(unsigned int i=0; i<6; i++){
			fscanf(fp, "%d", &ptemppack->dim[i]);
		}



		if(packageset->numPackages == 0){
			packageset->pPackageSetHead=ptemppack;
			packageset->pPackageSetRear=ptemppack;
			ptemppack->pNextPack=NULL;
		}else{

			packageset->pPackageSetRear->pNextPack=ptemppack;
			packageset->pPackageSetRear=packageset->pPackageSetRear->pNextPack;
			ptemppack->pNextPack=NULL;
		}

		packageset->numPackages++;

	}//end while

}



// Load Package Set into memory
void LoadPackages_bak(FILE *fp, struct PACKAGESET *packageset) {
	packageset->numPackages = 0;	// initial package number
	char validfilter;				// validfilter means an '@'
	struct PACKAGE * ptemppack;

	while (!feof(fp)) {
		fscanf(fp, "%c", &validfilter);

		if (validfilter != '@'){
			continue;	// each rule should begin with an '@'
			}

		// malloc
		ptemppack=(struct PACKAGE *)malloc(sizeof(struct PACKAGE));
		if(NULL == ptemppack){
			printf("(malloc) load pack error !!!\n");
			exit(1);
		}

		fscanf(fp, "%d.%d.%d.%d", &ptemppack->highSIP[0], &ptemppack->highSIP[1], &ptemppack->lowSIP[0],
				&ptemppack->lowSIP[1]);
		fscanf(fp, "%d.%d.%d.%d", &ptemppack->highDIP[0], &ptemppack->highDIP[1], &ptemppack->lowDIP[0],
				&ptemppack->lowDIP[1]);
		fscanf(fp, "%d", &ptemppack->sPort);
		fscanf(fp, "%d", &ptemppack->dPort);

		// dealing with dim[6]
		ptemppack->dim[0] = ptemppack->highSIP[0];
		ptemppack->dim[0] <<= 8;
		ptemppack->dim[0] += ptemppack->highSIP[1];

		ptemppack->dim[1] = ptemppack->lowSIP[0];
		ptemppack->dim[1] <<= 8;
		ptemppack->dim[1] += ptemppack->lowSIP[1];

		ptemppack->dim[2] = ptemppack->highDIP[0];
		ptemppack->dim[2] <<= 8;
		ptemppack->dim[2] += ptemppack->highDIP[1];

		ptemppack->dim[3] = ptemppack->lowDIP[0];
		ptemppack->dim[3] <<= 8;
		ptemppack->dim[3] += ptemppack->lowDIP[1];

		ptemppack->dim[4] = ptemppack->sPort;
		ptemppack->dim[5] = ptemppack->dPort;

		if(packageset->numPackages == 0){
			packageset->pPackageSetHead=ptemppack;
			packageset->pPackageSetRear=ptemppack;
			ptemppack->pNextPack=NULL;
		}else{

			packageset->pPackageSetRear->pNextPack=ptemppack;
			packageset->pPackageSetRear=packageset->pPackageSetRear->pNextPack;
			ptemppack->pNextPack=NULL;
		}

		packageset->numPackages++;



#ifdef DEBUG_READIP
printf("\n__________________________input IP(%d)_________________________\n",packageset->numPackages);
printf("%-9s%-9s%-9s%-9s%-9s%-9s\n","SIP_h","SIP_l","DIP_h","DIP_l","sPort","dPort");
printf("%-9d%-9d%-9d%-9d%-9d%-9d\n",packageset->pPackageSetRear->dim[0],\
		packageset->pPackageSetRear->dim[1],\
		packageset->pPackageSetRear->dim[2],\
		packageset->pPackageSetRear->dim[3],\
		packageset->pPackageSetRear->dim[4],\
		packageset->pPackageSetRear->dim[5]);

#endif

	}//end while

}



void ReadPackFile() {
	// Read packages from file packageset.txt
	FILE *fp;						// filter set file pointer
	char filename[] = "ip.txt";
	fp = fopen(filename,"r");
	if (fp == NULL)
	{
	printf("Cannot open package set file \n");
	exit (0);
	}
//	exit (0);
	LoadPackages(fp, &g_packageset);	// loading packages...
	fclose(fp);
	printf("Read %d Packs\n", g_packageset.numPackages);
}


void StoreResults(){

	 FILE *fp;

	 char filename1[] = "result.txt";
	 fp = fopen(filename1,"w+");
	 if (fp == NULL)
	 {
	 printf("Cannot open lookupResult file \n");
	 exit (0);
	 }
	 for(unsigned int i=0;i<g_packageset.numPackages;i++){
		 fprintf(fp,"%d\n", LookupResult[i]);
	 }
	 fclose(fp);


	 printf("Storing %d Results\n", g_packageset.numPackages);
 }



/*
 * Function to set bit value (0 or 1), called by SetPhase0_Cell
 * call form : SetBmpBit(bmp,i,TRUE)
 * Return : void
 */
void SetBmpBit_ori(unsigned int *tbmp, unsigned int i, bool value) {
	/*
	 * tbmp指向bmp[32], i 是规则index， value 是start end 标志位
	 * k 与 pos 指示相应rule 在bmp 里的位置，k 是index ，pos 是32bit 内的位置
	 * ture 把rule 的相应位置1，false 置0
	 */
	unsigned int k, pos;
	k = SIZE - 1 - (i / LENGTH);
	pos = i % LENGTH;
	unsigned int tempInt = 1;
	tempInt <<= pos;
	if (value == TRUE)
		tbmp[k] |= tempInt;
	else {
		tempInt = ~tempInt;
		tbmp[k] &= tempInt;
	}
}

/*

 * Function to set bit value (0 or 1), called by SetPhase0_Cell
 * call form : SetBmpBit(bmp,i,TRUE)
 * Return : void
*/
void SetBmpBit(unsigned int *tbmp, unsigned int i, unsigned char flag) {

	unsigned int k, pos;
	k = SIZE - (i / LENGTH) - 1;
	pos = i % LENGTH;
	unsigned int mask = 1;
	mask <<= pos;
	if (flag == 1){
		tbmp[k] |= mask;
	}else if(flag == 0){
		mask = ~mask;
		tbmp[k] &= mask;
	}else{
		printf("Error in SetBmpBit(unsigned int *tbmp, unsigned int i, unsigned char flag)");
		exit(1);
	}
}

/*
 Initialize listEqs, called by SetPhase0_Cell
 call form : InitListEqs(phase0_Nodes[i].listEqs)
 return : void
 */
void InitListEqs(LISTEqS *ptrlistEqs) {
	ptrlistEqs->nCES = 0;
	ptrlistEqs->phead = NULL;
	ptrlistEqs->prear = NULL;
}

/*
 Compare two bmp, called by SearchBmp
 return: same -- TRUE ;  different -- FALSE
 */
bool CompareBmp(unsigned int *abmp, unsigned int *bbmp) {
	if ((abmp == NULL) || (bbmp == NULL)){
		return FALSE;
	}

	/*bmp[32] CBM[32]*/
	for (int i = 0; i < SIZE; i++){
		if ((*(abmp + i)) != (*(bbmp + i))){
			return FALSE;
		}
	}

	return TRUE;
}

/*
 Function to search bmp in listEqs, called by SetPhase0_Cell
 call form : SearchBmp(phase0_Nodes[i].listEqs,bmp)
 Return: if tbmp not exist in listEqs, return -1
 else return eqID of CES whose cbm matches tbmp
 */
int SearchBmp(LISTEqS *pListEqs, unsigned int *pbmp) {
	CES *tCES;

	if(pListEqs->phead==NULL){
		return -1;
	}else{
		tCES = pListEqs->phead;
	}

	/*遍历整个CES*/
	for (int i = 0; i < pListEqs->nCES; i++) {
		if (CompareBmp(tCES->cbm, pbmp)){
			return i;
		}else{
			tCES = tCES->pnext;
		}
	}
//	printf("no match...\n");
	return -1;
}

/*
 Add new CES to ListEqs, called by SetPhase0_Cell
 call form : AddListEqsCES(phase0_Nodes[i].listEqs,bmp)
 Return : the eqID of the new CES
 */
int AddListEqsCES(LISTEqS *ptrlistEqs, unsigned int *ptbmp) {
	CES *ptCES;
	ptCES = (CES *) malloc(sizeof(CES));
	if(NULL == ptCES){
		printf("malloc faild ...\n");
		exit(1);
	}

	if (ptrlistEqs->phead == NULL) {
		/*第一个CES*/
		ptCES->eqID = 0;
		for (int i = 0; i < SIZE; i++){
			ptCES->cbm[i] = ptbmp[i];
		}

		ptCES->pnext = NULL;

		// add new CES to tlistEqs
		ptrlistEqs->phead = ptCES;
		ptrlistEqs->prear = ptCES;
		ptrlistEqs->nCES = 1;
	} else {
		/*非第一个CES*/

		ptCES->eqID = ptrlistEqs->nCES;
		for (int i = 0; i < SIZE; i++){
			ptCES->cbm[i] = ptbmp[i];
		}
		ptCES->pnext = NULL;

		//挂上
		ptrlistEqs->prear->pnext = ptCES;
		ptrlistEqs->prear = ptCES;
		ptrlistEqs->nCES=ptrlistEqs->nCES+1;
	}

	return ptrlistEqs->prear->eqID;
}

/*
 Get rule cost number with highest priority, called by SetPhase2_Cell
 Note : used for packet matching more than 1 rules
 call form : cost = GetRuleCost(endBmp)
 return : cost number with highest priority
 */
int GetRuleCost(unsigned int *tbmp) {
	unsigned int tempInt;
	unsigned int tempValue;
	for (int k = SIZE - 1; k >= 0; k--) {

		tempInt = 1;
		for (int pos = 1; pos <= LENGTH; pos++) {

			tempValue = tbmp[k] & tempInt;
			if (tempValue)
				return ( LENGTH * (SIZE - 1 - k) + pos);
			tempInt <<= 1;
		}
	}
	//printf("!!! Lack of default rule!\nThere is no rule matched!\n");
	return -1;
}

/*
 Free listEqs space, called by SetPhase1_Cell() & SetPhase2_Cell()
 Function : release space after table is established
 return : void
 */
void FreeListEqs(LISTEqS *ptrlistEqs) {
	if (ptrlistEqs->phead == NULL)
		return;
	CES *tCES;

	for (int i = 0; i < ptrlistEqs->nCES; i++) {

		tCES = ptrlistEqs->phead;
		ptrlistEqs->phead = ptrlistEqs->phead->pnext;
		free(tCES);
	}
	ptrlistEqs->prear = NULL;
}



/*
 Find proper order to cut memory occupied
 improved by jiangyibo ---2015-08-20
 优化排列组合方法
 */
void
ReOrder_6_33_1_enum() {
	//init
	unsigned int con0[6]={0,1,2,3,4,5};
	unsigned int con1[6]={0,2,1,3,4,5};
	unsigned int con2[6]={0,3,1,2,4,5};
	unsigned int con3[6]={0,1,2,3,5,4};
	unsigned int con4[6]={0,2,1,3,5,4};
	unsigned int con5[6]={0,3,1,2,5,4};
	unsigned int *tid;
	unsigned long min=0xFFFFFFFF;
	unsigned long calc;


	/*	ip group, symmetry C42 = 3,
	 * 	port groupsymmetry C21 = 2.
	 * 	2*3=6
	 * */
	for(unsigned int con =0; con<6; con++){
		//con
		switch (con) {
		case 0:
			tid=con0;
			break;
		case 1:
			tid=con1;
			break;
		case 2:
			tid=con2;
			break;
		case 3:
			tid=con3;
			break;
		case 4:
			tid=con4;
			break;
		case 5:
			tid=con5;
			break;
		default:
			break;
		}

		//calc
		calc=(unsigned long) phase0_Nodes[tid[0]].listEqs.nCES \
					* (unsigned long) phase0_Nodes[tid[1]].listEqs.nCES \
					* (unsigned long) phase0_Nodes[tid[4]].listEqs.nCES \
					+ (unsigned long) phase0_Nodes[tid[2]].listEqs.nCES \
					* (unsigned long) phase0_Nodes[tid[3]].listEqs.nCES \
					* (unsigned long) phase0_Nodes[tid[5]].listEqs.nCES;
		if (calc< min){
				min=calc;
				for (int i = 0; i < 6; i++){dot[i] = tid[i];}
				}
		}
}


/*
 Find proper order to cut memory occupied
 improved by jiangyibo ---2015-08-20
 优化排列组合方法
 */
void FindOrder_6_33_1() {
	unsigned int tid[6];
	unsigned int tmp;
	for(int m=0;m<6;m++){tid[m] = m;}
	for(int m=0;m<6;m++){dot[m] = m;} //dot全局变量

	/*注意类型转换*/
	unsigned long min;
	min=0xFFFFFFFF;
	unsigned long calc;

	for(int i =2; i>=0; i--)
	{

		for(int j =3; j<=5; j++)
		{
			tmp=tid[i];
			tid[i]=tid[j];
			tid[j]=tmp;

			//遍历各种情况，选择min的情况并返给dot[6]全局变量
			calc=(unsigned long) phase0_Nodes[tid[0]].listEqs.nCES \
						* (unsigned long) phase0_Nodes[tid[1]].listEqs.nCES \
						* (unsigned long) phase0_Nodes[tid[2]].listEqs.nCES \
						+ (unsigned long) phase0_Nodes[tid[3]].listEqs.nCES \
						* (unsigned long) phase0_Nodes[tid[4]].listEqs.nCES \
						* (unsigned long) phase0_Nodes[tid[5]].listEqs.nCES;
			if (calc< min){
					min=calc;
					for (int i = 0; i < 6; i++){dot[i] = tid[i];}
					}

				tmp=tid[i];
				tid[i]=tid[j];
				tid[j]=tmp;
			}

	}

#ifdef DEBUG_ORDER
	printf("___________After ordering________ \n");
	for (int m = 0; m < 6; m++) {
		printf("nCES of phase0_Nodes[%d] is %d\n",dot[m],phase0_Nodes[dot[m]].listEqs.nCES);
	}
#endif

}

/*
 Find proper order to cut memory occupied
 */
void FindOrder_ori() {
	bool flag;
	//全局变量 dot[6]=[0,1,2,3,4,5]
	for (int m = 0; m < 6; m++) {
		dot[m] = m;
	}

	unsigned int tid[6];
	for (tid[0] = 0; tid[0] < 1; tid[0]++) {
		for (tid[1] = tid[0] + 1; tid[1] < 5; tid[1]++) {
			for (tid[2] = tid[1] + 1; tid[2] < 6; tid[2]++) {

				// set tid[3] ~ tid[5]
				for (int i = 3; i < 6; i++) {
					for (tid[i] = 0; tid[i] < 6; tid[i]++) {
						flag = 1;
						for (int j = 0; j < i; j++)
							if (tid[j] == tid[i]) {
								flag = 0;
								break;
							}
						if (flag == 1)
							break;
					}
				} //end set tid[3] ~ tid[5]

				// find better order
				/*
				 *  找最小的
				 *	dot[0]*dot[1]*dot[2]+dot[3]*dot[4]*dot[5]
				 */
				if ((phase0_Nodes[tid[0]].listEqs.nCES * phase0_Nodes[tid[1]].listEqs.nCES
						* phase0_Nodes[tid[2]].listEqs.nCES
						+ phase0_Nodes[tid[3]].listEqs.nCES * phase0_Nodes[tid[4]].listEqs.nCES
								* phase0_Nodes[tid[5]].listEqs.nCES)
						< (phase0_Nodes[dot[0]].listEqs.nCES * phase0_Nodes[dot[1]].listEqs.nCES
								* phase0_Nodes[dot[2]].listEqs.nCES
								+ phase0_Nodes[dot[3]].listEqs.nCES * phase0_Nodes[dot[4]].listEqs.nCES
										* phase0_Nodes[dot[5]].listEqs.nCES)) {
					for (int i = 0; i < 6; i++) {
						dot[i] = tid[i];
					}
				} //end if

			} //end for(tid[2]=tid[1]+1;tid[2]<6;tid[2]++)
		} //end for(tid[1]=tid[0]+1;tid[1]<5;tid[1]++)
	} //end for(tid[0]=0;tid[0]<1;tid[0]++)

	printf("After Ording, dot[] = \n");
	for (int m = 0; m < 6; m++) {printf("%d,",dot[m]);}
	printf("dot[] = \n");

}


/*
 Function to fill the table of Phase 0, called by main
 return : void
 */
void SetPhase0_Cell() {

	//build phase0_Nodes[0~5]
	for (unsigned int com = 0; com < 6; com++) {
		//Initialize
		unsigned int bmp[SIZE]; // 32*32=1024
		for (unsigned int i = 0; i < SIZE; i++){bmp[i] = 0;}
		InitListEqs(&phase0_Nodes[com].listEqs);


		// Scan through the number line looking for distinct equivalence classes
		for (unsigned int n = 0; n < 65536; n++) {
			/* 遍历整个65536 的 number line 空间 */

			//Initialize
			int tempeqID; //小心！！！
			unsigned int tempstart, tempend;

			// See if any rule starts or ends at n
			for (unsigned int i = 0; i < g_filtset.numFilters; i++) {
				/*
				 * 遍历所有1000 rules，找到每个rule 在chunk[com]的project
				 */
				tempstart = g_filtset.filtArr[i].dim[com][0];
				tempend = g_filtset.filtArr[i].dim[com][1];

				if (tempstart == n)
					SetBmpBit(bmp, i, TRUE); //bmp 为(unsign int *) 指向bmp[32]首地址
				if ((tempend + 1) == n)
					SetBmpBit(bmp, i, FALSE);
			} // 1000 rule  遍历结束


			/*
			 *  Search cbm of phase0_Nodes[com]->listEqs for bmp
			 *  return -1 if not exist, else return eqID
			 *  遍历比较已有的CBM和BMP
			 */
			tempeqID=-1;
			tempeqID = SearchBmp(&(phase0_Nodes[com].listEqs), bmp);
			/*
			 * Not exist, add bmp to listEqs，
			 * 在CES中添加新的CBM和eqID
			 */
			if (-1 == tempeqID){
				tempeqID = AddListEqsCES(&phase0_Nodes[com].listEqs, bmp);

#ifdef DEBUG_P0
				printf("______________________ set phase 0 __________________________\n");
				printf("____AddListEqs(phase0_Nodes[%d].listEqs)\n",com);
				printf("nCES = %d\n",phase0_Nodes[com].listEqs.nCES);

				printf("head = 0x%x\n",phase0_Nodes[com].listEqs.phead);
				printf("head->next = 0x%x\n",phase0_Nodes[com].listEqs.phead->pnext);
				printf("rear = 0x%x\n",phase0_Nodes[com].listEqs.prear);
				printf("bmp[31] = 0x%x\n",bmp[31]);
				printf("ces[31] = 0x%x\n",phase0_Nodes[com].listEqs.prear->cbm[31]);
				printf("eqID= %d\n",phase0_Nodes[com].listEqs.prear->eqID);
#endif


			}

			// Set Phase0 Cell bits
			phase0_Nodes[com].cell[n] = (unsigned short) tempeqID;
		} // 65536 line 遍历结束

	} //chunk[com]遍历结束
}

/*
 Function to fill the table of Phase 1, called by main
 return : void
 */
void SetPhase1_Cell() {
	struct PNODE *tnode1;
	struct PNODE *tnode2;
	struct PNODE *tnode3;

	// Chunk[0] ~ Chunk[1] of Phase 1
	for (int com = 0; com < 2; com++) {
		// Initialize
		unsigned int indx = 0;
		int tempeqID;
		InitListEqs(&phase1_Nodes[com].listEqs);

		// Dealing with different component
		/*3+3 phase0->1 reduction tree*/
		switch (com) {
		case 0:
			tnode1 = &phase0_Nodes[dot[0]];
			tnode2 = &phase0_Nodes[dot[1]];
			tnode3 = &phase0_Nodes[dot[2]];
			break;
		case 1:
			tnode1 = &phase0_Nodes[dot[3]];
			tnode2 = &phase0_Nodes[dot[4]];
			tnode3 = &phase0_Nodes[dot[5]];
			break;
		default:
			break;
		}/*switch 减少内存占用*/

		// alloc memory for Phase1 cell
		unsigned long cellNum;
		cellNum = (unsigned long)tnode1->listEqs.nCES * \
				(unsigned long)tnode2->listEqs.nCES * \
				(unsigned long)tnode3->listEqs.nCES;
		phase1_Nodes[com].ncells = cellNum;

		phase1_Nodes[com].cell = (unsigned short *) malloc(cellNum * sizeof(unsigned short));
		if(NULL == phase1_Nodes[com].cell){
			printf("malloc faild ...\n");
			exit(1);
		}

		// generate phase1_Nodes[com]->listEqs
		CES *tCES1, *tCES2, *tCES3;
		unsigned int intersectedBmp[SIZE]; //32*32=1024 bit

		tCES1 = tnode1->listEqs.phead;
		for (int i = 0; i < tnode1->listEqs.nCES; i++) {

			tCES2 = tnode2->listEqs.phead;
			for (int j = 0; j < tnode2->listEqs.nCES; j++) {

				tCES3 = tnode3->listEqs.phead;
				for (int k = 0; k < tnode3->listEqs.nCES; k++) {

					// generate intersectedBmp
					/*phase0 的CBM相与*/
					for (int m = 0; m < SIZE; m++){
						intersectedBmp[m] = tCES1->cbm[m] & tCES2->cbm[m] & tCES3->cbm[m];
					}

					// Search cbm of phase1_Nodes[com]->listEqs for intersectedBmp
					// return -1 if not exist, else return eqID
					tempeqID=-1;
					tempeqID = SearchBmp(&phase1_Nodes[com].listEqs, intersectedBmp);

					// Not exist, add intersectedBmp to listEqs
					if (-1 == tempeqID){
						tempeqID = AddListEqsCES(&phase1_Nodes[com].listEqs, intersectedBmp);

#ifdef DEBUG_P1
	printf("______________________ set phase 1 __________________________\n");
	printf("phase1_Nodes[com].ncell = %d\n",cellNum);
	printf("head = 0x%x\n",phase1_Nodes[com].listEqs.phead);
	printf("rear = 0x%x\n",phase1_Nodes[com].listEqs.prear);
	printf("bmp[31] = 0x%x\n",intersectedBmp[31]);
	printf("ces[31] = 0x%x\n",phase1_Nodes[com].listEqs.prear->cbm[31]);
	printf("eqID= %d\n",phase1_Nodes[com].listEqs.prear->eqID);
#endif

					}

					// Set Phase1 Cell bits
					phase1_Nodes[com].cell[indx] = (unsigned short) tempeqID;
					indx++;

					tCES3 = tCES3->pnext;
				}
				tCES2 = tCES2->pnext;
			}
			tCES1 = tCES1->pnext;
		}


		// Release listEqs Space
		FreeListEqs(&tnode1->listEqs);
		FreeListEqs(&tnode2->listEqs);
		FreeListEqs(&tnode3->listEqs);


	}/*end for (int com = 0; com < 2; com++)  chunk phase1*/
}

/*
 Function to fill the table of Phase 2, called by main
 return : void
 */
void SetPhase2_Cell() {
	unsigned int indx = 0;
	struct PNODER *tnode1;
	struct PNODER *tnode2;
	CES *tCES1, *tCES2;
	unsigned int endBmp[SIZE];
	int tempeqID;
	unsigned int cost;	// cost number with highest priority

	tnode1 = &phase1_Nodes[0];
	tnode2 = &phase1_Nodes[1];

	// Initialize phase2_Node.listEqs
	InitListEqs(&phase2_Node.listEqs);

	// alloc memory for Phase1 cell
	unsigned long cellNum;
	cellNum = (unsigned long)tnode1->listEqs.nCES * \
			(unsigned long)tnode2->listEqs.nCES;
	phase2_Node.ncells = cellNum;
	phase2_Node.cell = (unsigned short *) malloc(cellNum * sizeof(unsigned short));
	if(NULL == phase2_Node.cell){
		printf("malloc faild ......");
		exit(1);
	}

	tCES1 = tnode1->listEqs.phead;
	for (int i = 0; i < tnode1->listEqs.nCES; i++) {

		tCES2 = tnode2->listEqs.phead;
		for (int j = 0; j < tnode2->listEqs.nCES; j++) {

			// generate endBmp
			/*chunk in phase1 的 CBM 叉乘*/
			for (int m = 0; m < SIZE; m++){
				endBmp[m] = tCES1->cbm[m] & tCES2->cbm[m];
			}

			tempeqID=-1;
			tempeqID = SearchBmp(&phase2_Node.listEqs, endBmp);
			if (-1 == tempeqID){
				tempeqID = AddListEqsCES(&phase2_Node.listEqs, endBmp);
#ifdef DEBUG_P2
				printf("______________________ set phase 2 __________________________\n");
				printf("phase2_Nodes.ncell = %d\n",cellNum);
				printf("head = 0x%x\n",phase2_Node.listEqs.phead);
				printf("rear = 0x%x\n",phase2_Node.listEqs.prear);
				printf("bmp[31] = 0x%x\n",endBmp[31]);
				printf("ces[31] = 0x%x\n",phase2_Node.listEqs.prear->cbm[31]);
				printf("eqID= %d\n",phase2_Node.listEqs.prear->eqID);
#endif
			}

			// Get rule cost number with highest priority
			cost = GetRuleCost(endBmp);
			phase2_Node.cell[indx] = cost;
//			phase2_Node.cell[indx] = (unsigned short) tempeqID;
			indx++;

			tCES2 = tCES2->pnext;
		}//for (int j = 0; j < tnode2->listEqs.nCES; j++)
		tCES1 = tCES1->pnext;
	}//for (int i = 0; i < tnode1->listEqs.nCES; i++)

	// Release listEqs Space
	FreeListEqs(&tnode1->listEqs);
	FreeListEqs(&tnode2->listEqs);
}

/*
 Lookup, called by main
 the packages are in packageset.txt
 Result: save into lookupResult.txt
 */
void Lookup_ori() {
	/*
	 // Read packages from file packageset.txt
	 FILE *fp;						// filter set file pointer
	 char filename[] = "packageset.txt";
	 fp = fopen(filename,"r");
	 if (fp == NULL)
	 {
	 printf("Cannot open package set file \n");
	 exit (0);
	 }
	 LoadPackages(fp, &packageset);	// loading packages...
	 fclose(fp);
	 */

	// Lookup process
	int time;
	time = GetTickCount();

	/*
	 phase0 6个cid
	 phase1 2个cid
	 phase2 1个cid
	 phase0->1   2个index
	 phase1->2   1个index
	 */
	unsigned int cid[9];
	unsigned int indx[3];
	unsigned int line = 0;
	for (line = 0; line < 1000000; line++) {

		// phase 0
		for (int i = 0; i < 6; i++) {
			cid[i] = phase0_Nodes[i].cell[2];	//找的某一特定规则
		}

		// phase 1
		/*	仅仅验算查找时间！！！
		 *  index=a*Nb*NC+b*Nc+c
		 *	Nb，Nc就是eqID的最大数目
		 *  LISTEqS.nCES
		 * */
		indx[0] = cid[dot[0]] * 1 * 1 + cid[dot[1]] * 1 + cid[dot[2]];
		indx[1] = cid[dot[3]] * 1 * 2 + cid[dot[4]] * 2 + cid[dot[5]];
		cid[6] = phase1_Nodes[0].cell[indx[0]];
		cid[7] = phase1_Nodes[1].cell[indx[1]];

		// phase 2
		indx[2] = cid[6] * 2 + cid[7];


		// store lookup result into lookupResult[]
		LookupResult[line] = phase2_Node.cell[indx[2]];
	}	//end of 1000000 line
	time = GetTickCount() - time;
	printf("\nLookup finished! %d ms\n", time);

	/*	// store lookupResult int lookupResult.txt
	 char filename1[] = "lookupResult.txt";
	 fp = fopen(filename1,"w+");
	 if (fp == NULL)
	 {
	 printf("Cannot open lookupResult file \n");
	 exit (0);
	 }
	 for(unsigned int i=0;i<packageset.numPackages;i++){
	 fprintf(fp,"%d\n",lookupResult[i]);
	 }
	 fclose(fp);*/
}


/*
 Lookup, called by main
 the packages are in packageset.txt
 Result: save into lookupResult.txt
 */
void Lookup_package() {

	ReadPackFile();
/*
	pLookupResult = (unsigned short *) malloc((g_packageset.numPackages) * sizeof(unsigned short));
	if(NULL == pLookupResult){
		printf("malloc faild ...\n");
		exit(1);
	}*/

	/*
	 phase0 6个cid
	 phase1 2个cid
	 phase2 1个cid
	 phase0->1   2个index
	 phase1->2   1个index
	 */
	unsigned int cid[8];
	unsigned int indx[3];
	struct PACKAGE * pTmpPack;
	pTmpPack=g_packageset.pPackageSetHead;


//	printf("0x%x\n",g_packageset.pPackageSetHead);
	for (unsigned int line = 0; line < g_packageset.numPackages; line++){

		/*	phase 0 */
		for (int i = 0; i < 6; i++) {
			cid[i] = phase0_Nodes[i].cell[pTmpPack->dim[i]];
		}

		/*	phase 1 */
		indx[0] = cid[dot[0]] * phase0_Nodes[dot[1]].listEqs.nCES * phase0_Nodes[dot[2]].listEqs.nCES \
				+ cid[dot[1]] * phase0_Nodes[dot[2]].listEqs.nCES \
				+ cid[dot[2]];
		indx[1] = cid[dot[3]] * phase0_Nodes[dot[4]].listEqs.nCES * phase0_Nodes[dot[5]].listEqs.nCES \
				+ cid[dot[4]] * phase0_Nodes[dot[5]].listEqs.nCES \
				+cid[dot[5]];
		cid[6] = phase1_Nodes[0].cell[indx[0]];
		cid[7] = phase1_Nodes[1].cell[indx[1]];

		/* phase 2 */
		indx[2] = cid[6] * phase1_Nodes[1].listEqs.nCES + cid[7];


		// store lookup result into lookupResult[]
		LookupResult[line] = phase2_Node.cell[indx[2]];

		pTmpPack=pTmpPack->pNextPack;

	}	//end of line

	#ifdef DEBUG_LookUp
	printf("____________________Looking Up Results_______________________\n");
	printf("matched rules:\n");
	for(unsigned int line = 0; line < g_packageset.numPackages; line++){
		printf("%d,", LookupResult[line]);
	}
	printf("\n");
	#endif

}



/*
 count memory : memory occupied by chunks
 2 byte (u16) *
 (cell[65535] * 6 +
 ncells in phase1 +
 ncells in phase2)
 byte

 */
void CountMemory() {
	unsigned int tot_cellused;
	unsigned int numbits;
	unsigned int total;
	unsigned int p0_cellused,p1_cellused,p2_cellused;

	total=0;
	/*ncell 为unsigned short
	 *
	 * */
	numbits = sizeof(unsigned short);
	p0_cellused = 65536 * 6 * numbits;
	p1_cellused = phase1_Nodes[0].ncells* numbits;
	p1_cellused += phase1_Nodes[1].ncells* numbits;
	p2_cellused = phase2_Node.ncells* numbits;
	tot_cellused= p0_cellused+p1_cellused+p2_cellused;

	printf("\n%-12s%-12s%-12s \n","phase0","phase1","phase2");
	printf("%-12d%-12d%-12d [Bytes] \n", p0_cellused,p1_cellused,p2_cellused );

	printf("\nMemory totally used: %d MBytes\n", tot_cellused / 1024 /1024);

	//totally used
/*	total+=cellused;
	for (int i = 0; i < 6; i++){total+=phase0_Nodes[i].listEqs.nCES;}
	for (int i = 0; i < 2; i++){total+=phase1_Nodes[i].listEqs.nCES;}
	total+=phase2_Node.listEqs.nCES;

	printf("\nMemory used by chunks : %d bytes\n", cellused * numbits);
	printf("Memory totally used: %d bytes\n", total * numbits);*/

	// store memory used int memoryused.txt
	FILE *fp;
	char filename[] = "RFC_memorycost.txt";
	fp = fopen(filename, "w+");
	if (fp == NULL) {
		printf("Cannot open memoryused file \n");
		exit(1);
	}

	fprintf(fp,"\n______________RFC_________________________\n");

	fprintf(fp,"\n%-12s%-12s%-12s \n","phase0","phase1","phase2");
	fprintf(fp,"%-12d%-12d%-12d [Bytes] \n", p0_cellused,p1_cellused,p2_cellused );

	fprintf(fp,"\nMemory totally used: %d Bytes\n", tot_cellused);



	fclose(fp);
}

/*
 * save preprocessing result to chunkdata.txt
 * saving cell[65535]
 * saving CES (consisting of eqId and CBM)
 *
 */
void SaveTemporary() {
	FILE *fp;
	char filename[] = "chunkdata.txt";
	fp = fopen(filename, "w+");
	if (fp == NULL) {
		printf("Cannot open chunkdata.txt file \n");
		exit(1);
	}

	// Save phase0 chunks
	unsigned int i, j;
	/////////////////////////////////////////////////////////////////////////
	// Save phase0 chunk data
	for (i = 0; i < 6; i++){
		for (j = 0; j < 65536; j++){
			fprintf(fp, "%d\t", phase0_Nodes[i].cell[j]);
		}

	}


	// Save CES amount of chunk
	for (i = 0; i < 6; i++){
		fprintf(fp, "%d\t", phase0_Nodes[i].listEqs.nCES);
	}


	//////////////////////////////////////////////////////////////////////////
	// Save phase1 chunks
	for (i = 0; i < 2; i++) {
		// Save phase1 chunk cell numbers
		fprintf(fp, "%d\t", phase1_Nodes[i].ncells);
		for (j = 0; j < phase1_Nodes[i].ncells; j++) {
			fprintf(fp, "%d\t", phase1_Nodes[i].cell[j]);
		}
	}
	// Save CES amount of chunk
	for (i = 0; i < 2; i++){
		fprintf(fp, "%d\t", phase1_Nodes[i].listEqs.nCES);
	}


	///////////////////////////////////////////////////////////////////////////
	// Save phase2 chunk cell numbers
	fprintf(fp, "%d\t", phase2_Node.ncells);


	// Save phase2 chunk
	for (j = 0; j < phase2_Node.ncells; j++)
		fprintf(fp, "%d\t", phase2_Node.cell[j]);

	fclose(fp);
}


/*
 *  load preprocessing result from chunkdata.txt
 */
void LoadTempprary() {
	FILE *fp;
	char filename[] = "chunkdata.txt";
	fp = fopen(filename, "r");
	if (fp == NULL) {
		printf("Cannot open chunkdata.txt file \n");
		exit(1);
	}

	///////////////////////////////////////////////////
	// Load phase0 chunks
	unsigned int i, j;
	unsigned short tnCES;

	// Read chunk data
	for (i = 0; i < 6; i++)
		for (j = 0; j < 65536; j++) {
			fscanf(fp, "%d", &phase0_Nodes[i].cell[j]);
		}
	// Read CES amount of chunk
	for (i = 0; i < 6; i++) {
		fscanf(fp, "%d", &tnCES);
		phase0_Nodes[i].listEqs.nCES = tnCES;
	}

	////////////////////////////////////////////////////
	// Load phase1 chunks
	for (i = 0; i < 2; i++) {
		// Read phase1 chunk cell numbers
		fscanf(fp, "%d", &phase1_Nodes[i].ncells);

		// Allocate memory for phase1_Node[i] cells
		phase1_Nodes[i].cell = (unsigned short *) malloc(phase1_Nodes[i].ncells * sizeof(unsigned short));
		if(NULL == phase1_Nodes[i].cell){
			printf("malloc faild ...\n");
			exit(1);
		}

		// Load phase1_Nodes[i] chunk data
		for (j = 0; j < phase1_Nodes[i].ncells; j++) {
			fscanf(fp, "%d", &phase1_Nodes[i].cell[j]);
		}
	}

	//Read CES amount of chunk
	for (i = 0; i < 2; i++) {
		fscanf(fp, "%d", &tnCES);
		phase1_Nodes[i].listEqs.nCES = tnCES;
	}

	////////////////////////////////////////////////////
	// Read phase2 chunk cell numbers
	fscanf(fp, "%d", &phase2_Node.ncells);

	// Allocate memory for phase2_Node cells
	phase2_Node.cell = (unsigned short *) malloc(phase2_Node.ncells * sizeof(unsigned short));
	if(NULL == phase2_Node.cell){
		printf("malloc faild ...\n");
		exit(1);
	}

	// Load phase2 chunk data
	for (j = 0; j < phase2_Node.ncells; j++)
		fscanf(fp, "%d", &phase2_Node.cell[j]);

	fclose(fp);
}

/*
 preprocessing according to filterset
 Aim : To establish the chunks & save to file chunkdata.txt
 */
void Preprocess() {
	/*	3 phase RFC*/
	SetPhase0_Cell();

    // Find order to cut memory occupied
//    ReOrder_6_33_1_enum();
    FindOrder_6_33_1();


	SetPhase1_Cell();

	SetPhase2_Cell();

	CountMemory();

	/*
	 * saving cell[65535]
	 * saving CES (consisting of eqId and CBM)
	 */
	SaveTemporary();
}

int main(int argc, char* argv[]) {

// reading data
	ReadFilterFile();

//	PROFILE_START
	Preprocess();
//	printf("build chunk data........");
//	PROFILE_END

//	PROFILE_START
	Lookup_package();
//	printf("lookup........");
//	PROFILE_END
	CountMemory();
	StoreResults();

	cRFC_6F();
	CountMemory_CRFC();



	return 0;
}
