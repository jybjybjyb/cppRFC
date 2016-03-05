
#ifndef CPP_RFC_H_
#define CPP_RFC_H_

/*function declaration for RFC.CPP*/
#include "cRFC.h"


/*predefination*/

#define MAXFILTERS	1000	// maximum amount of filters, 1000 for test
#define MAXPACKAGES 1000	// maximum amount of packages, 1000 for test

#define TRUE			1
#define FALSE			0
#define SUCCESS         1
#define LENGTH			32				// length of unsigned int
#define SIZE			32			    // SIZE = ceiling ( rules / LENGTH )
#define DIM			6




extern struct FILTSET g_filtset;

extern struct PACKAGESET g_packageset;


// structure for Phase 0
extern struct PNODE phase0_Nodes[6];
extern struct CompressComponent  CompressBitMap_p0[6];


// structure for Phase 1
extern struct PNODER phase1_Nodes[2];
extern struct CompressComponent  CompressBitMap_p1[2];

// structure for Phase 2
extern struct PNODER phase2_Node;


// structure for lookup result
extern unsigned int LookupResult[MAXPACKAGES];

// Find proper order to cut memory occupied
extern unsigned int dot[6];




//	structures for filters...
struct FILTER {
	// the bytes needed in practice, totally
	unsigned int 	cost;				// 4 bytes, ����Ĵ���, �������ڹ�����е������, ���ǹ����line���
	unsigned char  	act;				// 1 byte, ִ������
	unsigned int	dim[6][2];			// refer to the start & end of every dimension

};

struct FILTSET
{
	unsigned int	numFilters;				// ��������
	struct FILTER	filtArr[MAXFILTERS];	// ��Ź���Ŀռ�, ���������Թ��������̬�����ڴ�
};

//	structures for packages...
struct PACKAGE
{

	unsigned int  	highSIP[2];			// 2 bytes, sIP�ĸ�2�ֽ�
	unsigned int  	lowSIP[2];			// 2 bytes, sIP�ĵ�2�ֽ�
	unsigned int  	highDIP[2];			// 2 bytes, dIP�ĸ�2�ֽ�
	unsigned int  	lowDIP[2];			// 2 bytes, dIP�ĵ�2�ֽ�
	unsigned int  	sPort;				// 2 bytes, 16λԴ�Ͽ�, �����16λ��ռ��32λ�ڴ�
	unsigned int 	dPort;				// 2 bytes, 16λĿ��˿�, �����16λ��ռ��32λ�ڴ�
	unsigned int	dim[6];				// ά�� refer to all the dimension��chunk
	struct PACKAGE * pNextPack;
};

struct PACKAGESET
{
	unsigned int	numPackages;				// ��������
	struct PACKAGE *	pPackageSetHead;
	struct PACKAGE *	pPackageSetRear;
//	struct PACKAGE	PackArr[MAXPACKAGES];		// ��������Ŀռ�, ��������������������̬�����ڴ�
};


/*pnode
 * IPT cell[65536]��LISTEqS��
 * IPT cell[65536]����eqID ��CES ��
 * */


// structure for CES...
struct CES
{
	unsigned short eqID;				// eqID��16bit = 0~65535,����Χ����16λ,���65536��rules;
	unsigned int  cbm[SIZE];			// CBM��LENGTH��SIZE=32*32=1024 bits ��Ӧ 1000rules
	struct CES *pnext;							// next CES
};



// structure for List of CES
struct LISTEqS
{
	unsigned short nCES;				// number of CES
	struct CES *phead;							// head pointer of LISTEqS
	struct CES *prear;							// pointer to end node of LISTEqS
};

// structure for Phase0 node
struct PNODE
{
	unsigned short cell[65536];	// each cell stores an eqID�� ���IPT����Χ��0~65535��16bit�� number line �ռ�
	struct LISTEqS listEqs;			// list of Eqs
};

// structure for Phase1 & Phase2 node
struct PNODER
{
	unsigned long ncells;				// IPT��index��
	unsigned short *cell;				// dynamic alloc cell of chunk in phase1
	struct LISTEqS listEqs;
};



#endif
/*function declaration*/
void ReadPackFile();

