#ifndef _SECURITY_ACCESS_H_
#define _SECURITY_ACCESS_H_
#include "binary.h"

namespace nsp_dfcv_security_access
{
	void CalcSecuAccess(int nMode, const TString& strMask, const CBinary& binRecvSeed, CBinary& binCmdKey);

	/*
		异或算法
		例如：
		00 00 00 01  ->  13 F0 C3 C6
		00 00 00 02  ->  27 E1 87 8C
		00 00 00 03  ->  34 11 44 4A
		00 00 00 01 ^ 00 00 00 02 = 00 00 00 03
		13 F0 C3 C6 ^ 27 E1 87 8C =  34 11 44 4A
	*/
	void CalcSecuAccess_Mode01(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
		玉柴Econtrols 4G CAN系统。
		FD630200118D
		FD7305A23C50D3008a
	*/
	void CalcSecuAccess_Mode02(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	void CalcSecuAccess_Mode03(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);
	void CalcSecuAccess_Mode04(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);
	void CalcSecuAccess_Mode05(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);
	void CalcSecuAccess_Mode06(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);
	void CalcSecuAccess_Mode07(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);
	void CalcSecuAccess_Mode08(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
		两个字节的异或算法
		Req=82 10 F1 27 09 B3
		Res=84 F1 10 67 09 00 01 F6
		Req=84 10 F1 27 0A 8C 90 D2
		Res=84 F1 10 67 0A 00 00 F6

		Req=82 10 F1 27 09 B3
		Res=84 F1 10 67 09 00 02 F7
		Req=84 10 F1 27 0A 60 3A 50
		Res=84 F1 10 67 0A 00 00 F6

		Req=82 10 F1 27 09 B3
		Res=84 F1 10 67 09 00 03 F8
		Req=84 10 F1 27 0A EC AA 4C
		Res=84 F1 10 67 0A 00 00 F6
		01 ^ 02 = 03
		8C 90 ^ 60 3A = EC AA
	*/
	void CalcSecuAccess_Mode09(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	4D20博世电控系统(国4 2013款)
	(1)
	Req=08 07 E0 02 27 0B 00 00 00 00 00
	Res=08 07 E8 06 67 0B 54 13 49 99 00
	Req=08 07 E0 06 27 0C AE FC 4F 31 00
	Res=08 07 E8 02 67 0C 00 00 00 00 00

	(2)
	Req=08 07 E0 02 27 0B 00 00 00 00 00
	Res=08 07 E8 06 67 0B 20 41 95 75 00
	Req=08 07 E0 06 27 0C A4 3F B1 30 00
	Res=08 07 E8 02 67 0C 00 00 00 00 00

	(3)
	Req=08 07 E0 02 27 0B 00 00 00 00 00
	Res=08 07 E8 06 67 0B 49 21 51 15 00
	Req=08 07 E0 06 27 0C CD 5F 77 17 00
	Res=08 07 E8 02 67 0C 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode0A(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	(1)
	Req=88 18 DA 00 FA 02 27 03 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 03 45 22 82 21 00
	Req=88 18 DA 00 FA 06 27 04 34 B6 29 C6 00
	Res=88 18 DA FA 00 06 67 04 00 00 00 00 00

	(2)
	Req=88 18 DA 00 FA 02 27 03 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 03 86 32 64 07 00
	Req=88 18 DA 00 FA 06 27 04 F9 F6 FC ED 00
	Res=88 18 DA FA 00 06 67 04 00 00 00 00 00

	(3)
	Req=88 18 DA 00 FA 02 27 03 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 03 65 16 09 32 00
	Req=88 18 DA 00 FA 06 27 04 DA 88 90 19 00
	Res=88 18 DA FA 00 06 67 04 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode0B(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	(1)
	Req=88 18 DA 00 F1 02 27 01 00 00 00 00 00
	Res=88 18 DA F1 00 06 67 01 51 14 77 43 00
	Req=88 18 DA 00 F1 06 27 02 A5 9D 99 53 00
	Res=88 18 DA F1 00 03 67 02 00 00 00 00 00

	(2)
	Req=88 18 DA 00 F1 02 27 01 00 00 00 00 00
	Res=88 18 DA F1 00 06 67 01 98 20 34 15 00
	Req=88 18 DA 00 F1 06 27 02 E6 57 05 67 00
	Res=88 18 DA F1 00 03 67 02 00 00 00 00 00

	(3)
	Req=88 18 DA 00 F1 02 27 01 00 00 00 00 00
	Res=88 18 DA F1 00 06 67 01 18 48 61 03 00
	Req=88 18 DA 00 F1 06 27 02 60 95 0D 32 00
	Res=88 18 DA F1 00 03 67 02 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode0C(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	1.EDC17_CP_V771
	(1)
	Req=88 18 DA 00 FA 02 27 1B 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 1B 45 15 42 98 00
	Req=88 18 DA 00 FA 06 27 1C 43 06 BC F8 00
	Res=88 18 DA FA 00 02 67 1C 00 00 00 00 00

	(2)
	Req=88 18 DA 00 FA 02 27 1B 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 1B 85 31 41 19 00
	Req=88 18 DA 00 FA 06 27 1C 58 F4 9F 10 00
	Res=88 18 DA FA 00 02 67 1C 00 00 00 00 00

	(3)
	Req=88 18 DA 00 FA 02 27 1B 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 1B 32 61 48 13 00
	Req=88 18 DA 00 FA 06 27 1C CF 1D 7C 88 00
	Res=88 18 DA FA 00 02 67 1C 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode0D(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	(1)
	Req=88 18 DA 00 FB 02 27 09 00 00 00 00 00
	Res=88 18 DA FB 00 06 67 09 15 35 81 60 00
	Req=88 18 DA 00 FB 06 27 0A FF 74 6A 10 00
	Res=88 18 DA FB 00 02 67 0A 00 00 00 00 00

	(2)
	Req=88 18 DA 00 FB 02 27 09 00 00 00 00 00
	Res=88 18 DA FB 00 06 67 09 81 51 02 35 00
	Req=88 18 DA 00 FB 06 27 0A 29 50 DA F0 00
	Res=88 18 DA FB 00 02 67 0A 00 00 00 00 00

	(3)
	Req=88 18 DA 00 FB 02 27 09 00 00 00 00 00
	Res=88 18 DA FB 00 06 67 09 23 65 56 84 00
	Req=88 18 DA 00 FB 06 27 0A 57 8A 1E 38 00
	Res=88 18 DA FB 00 02 67 0A 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode0E(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	(1)
	Req=08 07 E0 02 27 01 00 00 00 00 00
	Res=08 07 E8 06 67 01 18 48 61 03 00
	Req=08 07 E0 06 27 02 36 E1 EC 6D 00
	Res=08 07 E8 02 67 02 00 00 00 00 00

	(2)
	Req=08 07 E0 02 27 01 00 00 00 00 00
	Res=08 07 E8 06 67 01 19 42 16 81 00
	Req=08 07 E0 06 27 02 0F 0F 3A 0E 00
	Res=08 07 E8 02 67 02 00 00 00 00 00

	(3)
	Req=08 07 E0 02 27 01 00 00 00 00 00
	Res=08 07 E8 06 67 01 71 56 81 04 00
	Req=08 07 E0 06 27 02 AA E2 F8 C2 00
	Res=08 07 E8 02 67 02 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode0F(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	上汽大通房车-SV61-RV80
	add by huangzefeng 20200921
	（1）
	Req = 08 07 E0 02 27 01 00 00 00 00 00
	Res = 08 07 E8 06 67 01 44 84 16 08 00
	Req = 08 07 E0 06 27 02 59 A8 FE 1C 00
	Res = 08 07 E8 02 67 02 00 00 00 00 00
	（2）
	Req = 08 07 E0 02 27 01 00 00 00 00 00
	Res = 08 07 E8 06 67 01 31 81 84 20 00
	Req = 08 07 E0 06 27 02 E0 2D 86 BC 00
	Res = 08 07 E8 02 67 02 00 00 00 00 00
	（3）
	Req = 08 07 E0 02 27 01 00 00 00 00 00
	Res = 08 07 E8 06 67 01 61 13 05 48 00
	Req = 08 07 E0 06 27 02 5A 2B 66 E0 00
	Res = 08 07 E8 02 67 02 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode10(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	/*
	KT770 华菱星马天然气国六系统的高级功能进入安全算法
	add by huangzefeng at 2020/9/28
	（1）
	Req=88 18 DA 00 F1 02 27 01 00 00 00 00 00
	Res=88 18 DA F1 00 06 67 01 2F B3 20 6C 00
	Req=88 18 DA 00 F1 06 27 02 DF 78 7E 26 00
	Res=88 18 DA F1 00 02 67 02 00 00 00 00 00
	（2）
	Req=88 18 DA 00 F1 02 27 01 00 00 00 00 00
	Res=88 18 DA F1 00 06 67 01 81 56 2A 70 00
	Req=88 18 DA 00 F1 06 27 02 81 FB 94 86 00
	Res=88 18 DA F1 00 02 67 02 00 00 00 00 00
	（3）
	Req=88 18 DA 00 F1 02 27 01 00 00 00 00 00
	Res=88 18 DA F1 00 06 67 01 21 A3 8F 4C 00
	Req=88 18 DA 00 F1 06 27 02 DE 7C 9E DC 00
	Res=88 18 DA F1 00 02 67 02 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode11(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	void CalcSecuAccess_Mode12(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	void CalcSecuAccess_Mode13(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);

	void CalcSecuAccess_Mode14(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);

	void CalcSecuAccess_Mode15(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);

	void CalcSecuAccess_Mode16(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);

	void CalcSecuAccess_Mode17(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-4-19:添加江西五十铃车身系统BCM安全算法
	void CalcSecuAccess_Mode18(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-4-20:添加江西五十铃万安气制动ABS安全算法
	void CalcSecuAccess_Mode19(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-4-21:添加江西五十铃发动机系统安全算法
	void CalcSecuAccess_Mode1A(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);	//电池管理系统
	void CalcSecuAccess_Mode1B(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);	//整车控制器
	void CalcSecuAccess_Mode1C(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);	//信号处理盒
	void CalcSecuAccess_Mode1D(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);	//转向角系统
	void CalcSecuAccess_Mode1E(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);	//BMS
	void CalcSecuAccess_Mode1F(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey); //DCAC DCDC
	void CalcSecuAccess_Mode20(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey); //D-MAX 国五发动机系统
	void CalcSecuAccess_Mode21(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey); //铃拓 国五发动机系统
	void CalcSecuAccess_Mode22(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey); //瑞迈S 汽油发动机系统

	//添加二期开发江西五十铃安全算法
	
	void CalcSecuAccess_Mode2B(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode2C(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode2D(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode2E(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode2F(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode30(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode31(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode32(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode33(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode34(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by zkh - 2021-5-20:添加江西五十铃安全算法
	void CalcSecuAccess_Mode35(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by yangkang
	void CalcSecuAccess_Mode36(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey);  //Add by yagnkang
	void CalcSecuAccess_Mode3A(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);  //Add by fz
	void CalcSecuAccess_Mode3B(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);  //Add by fz
	CGroup<UINT> GetSecurityAccessMask(const TString& strMask, int nLen);
	UINT GetSecurityAccessSeed(const CBinary& binSeed);
	CBinary GetSecurityAccessKey(UINT nKey, int nLen);

	//后处理-DDi13-迪耐斯国六
	void CalcSecuAccess_Mode57(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey);
	void DGX_BCM_method(UINT* uD_I32_0, UINT* uD_I32_1);
	BOOL DGX_BCM_Security_59(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey);
	void DGX_LDCM_method(UINT* uD_I32_0, UINT* uD_I32_1);
	BOOL DGX_LDCM_Security_5A(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey);
	void DGX_RDCM_method(UINT* uD_I32_0, UINT* uD_I32_1);
	BOOL DGX_RDCM_Security_5B(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey);
	void DGX_CIOM_method(UINT* uD_I32_0, UINT* uD_I32_1);
	BOOL DGX_CIOM_Security_5C(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey);
	UINT DFCV_EECU_method(UINT* a1, UINT* a2);
	BOOL DFCV_EECU_Security_60(const CBinary& ucSeed, CBinary& ucKey, int iMode);
	void SeedToKeyForDFCV_EBP_Mode01(const CBinary& ucSeed, CBinary& ucKey);
	void SeedToKeyForDFCV_ABS_VIE(const CBinary& ucSeed, CBinary& ucKey);
	void SeedToKeyForDFCV_PEPS_Mode03(const CBinary& ucSeed, CBinary& ucKey);
	void SeedToKeyForDFCV_DFCV_AMT2_Mode01(const CBinary& ucSeed, CBinary& ucKey);
	void SeedToKeyForDFCV_YZS_AEBS_R(const CBinary& ucSeed, CBinary& ucKey);
	void SeedToKeyForDFCV_KT1B_TCU(const CBinary& ucSeed, CBinary& ucKey);
	void SeedToKeyForDFCV_DGi13(const CBinary& ucSeed, CBinary& ucKey);
	void SaftySeedForDFLZ_L2EV(const CBinary& ucInput, CBinary& ucOutput);
	void  Seed2Key_JL_EHPS(const CBinary& ucInput, CBinary& ucOutput);
	void  SaftySeedForDFCV_AMT3(const CBinary& ucInput, CBinary& ucOutput);
	void  SaftySeedForDFCV_INS_III(const CBinary& ucInput, CBinary& ucOutput);
}
#endif //_SECURITY_ACCESS_H_