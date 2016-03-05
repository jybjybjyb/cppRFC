/*
 * GolbalVer.h
 *
 *  Created on: 2015年9月30日
 *      Author: 10177270
 */

#ifndef GLOBALVER_H_
#define GLOBALVER_H_

#include "RFC.h"
#include "cRFC.h"

/*
 * global 参数
 * phase0 的6 个pnode，也包括了相应的 LISTEqS， CES， cell[]
 * phase1 的2 个pnoder
 * phase0 的1 个pnoder
 *
 * */


struct FILTSET g_filtset;

struct PACKAGESET g_packageset;


// structure for Phase 0
struct PNODE phase0_Nodes[6];
struct CompressComponent  CompressBitMap_p0[6];


// structure for Phase 1
struct PNODER phase1_Nodes[2];
struct CompressComponent  CompressBitMap_p1[2];

// structure for Phase 2
struct PNODER phase2_Node;


// structure for lookup result
unsigned int LookupResult[MAXPACKAGES];

// Find proper order to cut memory occupied
unsigned int dot[6];


/*

double dff;
long long  c1, c2;
LARGE_INTEGER  large_interger;
#define PROFILE_START QueryPerformanceFrequency(&large_interger);\
							dff = large_interger.QuadPart;\
							QueryPerformanceCounter(&large_interger);\
							c1 = large_interger.QuadPart;


#define PROFILE_END QueryPerformanceCounter(&large_interger);\
							c2 = large_interger.QuadPart;\
							printf("计时%.2f毫秒\n", (c2 - c1) * 1000 / dff);\

*/

#endif /* GLOBALVER_H_ */
