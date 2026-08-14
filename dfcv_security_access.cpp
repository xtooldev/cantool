#include "stdafx.h"
#include "define.h"
#include "dfcv_module_data.h"
#include "dfcv_security_access.h"
#include "dfcv_public.h"
#include "dfcv_sha1_b3.h"
#include "VMProtectSDK.h"
//#include<windows.h>
#include <iostream>

using namespace nsp_dfcv_public;
using namespace nsp_dfcv_sha1_b3;

namespace nsp_dfcv_security_access
{
	template<class T> T ROL(T value, int count)
	{
		const UINT nbits = sizeof(T) * 8;

		if (count > 0)
		{
			count %= nbits;
			T high = value >> (nbits - count);
			if (T(-1) < 0) // signed value
				high &= ~((T(-1) << count));
			value <<= count;
			value |= high;
		}
		else
		{
			count = -count % nbits;
			T low = value << (nbits - count);
			value >>= count;
			value |= low;
		}
		return value;
	}
	inline BYTE  __ROL1__(BYTE  value, int count) { return ROL((BYTE)value, count); }
	inline UINT __ROL4__(UINT value, int count) { return ROL((UINT)value, count); }
	inline UINT __ROR4__(UINT value, int count) { return ROL((UINT)value, -count); }

	void CalcSecuAccess(int nMode, const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{

		switch (nMode & 0xFF)
		{
		case 0x01:
			CalcSecuAccess_Mode01(strMask, binRecvSeed, binKey);
			break;
		case 0x02:
			CalcSecuAccess_Mode02(strMask, binRecvSeed, binKey);
			break;
		case 0x03:
			CalcSecuAccess_Mode03(strMask, binRecvSeed, binKey);
			break;
		case 0x04:
			CalcSecuAccess_Mode04(strMask, binRecvSeed, binKey);
			break;
		case 0x05:
			CalcSecuAccess_Mode05(strMask, binRecvSeed, binKey);
			break;
		case 0x06:
			CalcSecuAccess_Mode06(strMask, binRecvSeed, binKey);
			break;
		case 0x07:
			CalcSecuAccess_Mode07(strMask, binRecvSeed, binKey);
			break;
		case 0x08:
			CalcSecuAccess_Mode08(strMask, binRecvSeed, binKey);
			break;
		case 0x09:
			CalcSecuAccess_Mode09(strMask, binRecvSeed, binKey);
			break;
		case 0x0A:
			CalcSecuAccess_Mode0A(strMask, binRecvSeed, binKey);
			break;
		case 0x0B:
			CalcSecuAccess_Mode0B(strMask, binRecvSeed, binKey);
			break;
		case 0x0C:
			CalcSecuAccess_Mode0C(strMask, binRecvSeed, binKey);
			break;
		case 0x0D:
			CalcSecuAccess_Mode0D(strMask, binRecvSeed, binKey);
			break;
		case 0x0E:
			CalcSecuAccess_Mode0E(strMask, binRecvSeed, binKey);
			break;
		case 0x0F:
			CalcSecuAccess_Mode0F(strMask, binRecvSeed, binKey);
			break;
		case 0x10:
			CalcSecuAccess_Mode10(strMask, binRecvSeed, binKey);
			break;
		case 0x11:
			CalcSecuAccess_Mode11(strMask, binRecvSeed, binKey);
			break;
		case 0x12:
			CalcSecuAccess_Mode12(strMask, binRecvSeed, binKey);
			break;
		case 0x13:
			CalcSecuAccess_Mode13(strMask, binRecvSeed, binKey);
			break;
		case 0x14:
			CalcSecuAccess_Mode14(strMask, binRecvSeed, binKey);
			break;
		case 0x15:
			CalcSecuAccess_Mode15(strMask, binRecvSeed, binKey);
			break;
		case 0x16:
			CalcSecuAccess_Mode16(strMask, binRecvSeed, binKey);
			break;
		case 0x17:
			CalcSecuAccess_Mode17(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-19:添加江西五十铃车身系统BCM安全算法
			break;
		case 0x18:
			CalcSecuAccess_Mode18(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-20:添加江西五十铃万安气制动ABS安全算法
			break;
		case 0x19:
		case 0x1A:
		case 0x1B:
			CalcSecuAccess_Mode19(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃发动机系统安全算法
			break;
		case 0x1C:
			CalcSecuAccess_Mode1A(strMask, binRecvSeed, binKey);//Add by yk 
			break;
		case 0x1D:
			CalcSecuAccess_Mode1B(strMask, binRecvSeed, binKey);//Add by yk
			break;
		case 0x1E:
			CalcSecuAccess_Mode1C(strMask, binRecvSeed, binKey);//Add by yk 
			break;
		case 0x1F:
			CalcSecuAccess_Mode1D(strMask, binRecvSeed, binKey);//Add by yk 
			break;
		case 0x20:
		case 0x21://DCAC
			CalcSecuAccess_Mode1E(strMask, binRecvSeed, binKey);//Add by yk 
			break;
		case 0x22://DCDC
		case 0x23://PDU
		case 0x24://MCU
		case 0x25://VCU SecAccMask=02
		case 0x26://IC SecAccMask=03
		case 0x27://BCM SecAccMask=04
		case 0x28://MP5 SecAccMask=05
		case 0x29://T-BOX SecAccMask=06
		case 0x2A://ABS SecAccMask=07
			CalcSecuAccess_Mode1F(strMask, binRecvSeed, binKey);//Add by yk
			break;	
		case 0x2B:
			CalcSecuAccess_Mode2B(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x2C:
			CalcSecuAccess_Mode2C(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x2D:
			CalcSecuAccess_Mode2D(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x2E:
			CalcSecuAccess_Mode2E(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x2F:
			CalcSecuAccess_Mode2F(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x30:
			CalcSecuAccess_Mode30(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x31:
			CalcSecuAccess_Mode31(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x32:
			CalcSecuAccess_Mode32(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x33:
			CalcSecuAccess_Mode33(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x34:
			CalcSecuAccess_Mode34(strMask, binRecvSeed, binKey); //Add by zkh - 2021-4-21:添加江西五十铃安全算法
			break;
		case 0x35://D-MAX 国五发动机系统
			CalcSecuAccess_Mode20(strMask, binRecvSeed, binKey);
			break;
		case 0x36://铃拓 国五发动机系统
			CalcSecuAccess_Mode21(strMask, binRecvSeed, binKey);
			break;
		case 0x37:
			CalcSecuAccess_Mode22(strMask, binRecvSeed, binKey);
			break;
		case 0x38:
			CalcSecuAccess_Mode35(strMask, binRecvSeed, binKey);
			break;
		case 0x39:
			CalcSecuAccess_Mode36(strMask, binRecvSeed, binKey);
			break;
		case 0x3A:
			CalcSecuAccess_Mode3A(strMask, binRecvSeed, binKey);
			break;
		case 0x3B:
			CalcSecuAccess_Mode3B(strMask, binRecvSeed, binKey);
			break;
		case 0x57:
			CalcSecuAccess_Mode57(strMask, binRecvSeed, binKey);
			break;
		case 0x59:
			DGX_BCM_Security_59(binRecvSeed, 4, 7, binKey);
			break;
		case 0x5A:
			DGX_LDCM_Security_5A(binRecvSeed, 4, 7, binKey);
			break;
		case 0x5B:
			DGX_RDCM_Security_5B(binRecvSeed, 4, 7, binKey);
			break;//
		case 0x5C:
			DGX_CIOM_Security_5C(binRecvSeed, 4, 7, binKey);
			break;//
		case 0x60://自主国六发动机
			DFCV_EECU_Security_60(binRecvSeed, binKey, 3);
			break;
		case 0x61://自动变速箱-东风-DA12
			SeedToKeyForDFCV_DFCV_AMT2_Mode01(binRecvSeed, binKey);
			break;
		case 0x62://天然气-DGi13
			SeedToKeyForDFCV_DGi13(binRecvSeed, binKey);
			break;
		case 0x63://万安ABS/EBS
			SeedToKeyForDFCV_ABS_VIE(binRecvSeed, binKey);
			break;
		case 0x68://科密-电子手刹EPB
			SeedToKeyForDFCV_EBP_Mode01(binRecvSeed, binKey);
			break;
		case 0x6A://无钥匙进入控制器-PEPS
			SeedToKeyForDFCV_PEPS_Mode03(binRecvSeed, binKey);
			break;
		case 0x71://电驱桥TCU
			SeedToKeyForDFCV_KT1B_TCU(binRecvSeed, binKey);
			break;
		case 0x76://YZS_AEBS_R	月照松AEBS-雷达
			SeedToKeyForDFCV_YZS_AEBS_R(binRecvSeed, binKey);
			break;
		case 0x79://L2EV发动机系统_CAN
			SaftySeedForDFLZ_L2EV(binRecvSeed, binKey);
			break;
		case 0x92:
			Seed2Key_JL_EHPS(binRecvSeed, binKey);
			break;
		case 0x93://自动变速箱-东风-DA08
			SaftySeedForDFCV_AMT3(binRecvSeed, binKey);
			break;
		case 0x94:
			SaftySeedForDFCV_INS_III(binRecvSeed, binKey);
			break;
		default:
			break;
		}
	}

	void CalcSecuAccess_Mode01(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 8);

		if (32 != groupMask.size())
		{
			return;
		}

		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);
		UINT nKey = 0x00;

		for (WORD i = 0; i < groupMask.size(); ++i)
		{
			if (nSeed & (0x01 << i))
			{
				nKey ^= groupMask[i];
			}
		}

		binKey = GetSecurityAccessKey(nKey, 4);
	}

	/*
		玉柴Econtrols 4G CAN系统。
	*/
	void CalcSecuAccess_Mode02(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		if (4 != binRecvSeed.m_nSize)
		{
			return;
		}

		UINT nSeed = 0xF347FE88;
		UINT nKey = 0x00;

		if ("0E" == strMask)
		{
			nSeed = 0xB792C87D;
		}
		nSeed ^= (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		nSeed ^= ((nSeed << 27) | (nSeed >> 5));
		nKey = nSeed;

		for (int i = 0; i < 4; ++i)
		{
			binKey += (BYTE)((nKey >> ((3 - i) * 8)) & 0xFF);
		}

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}


	/*
	(1)
	Req=08 07 E0 02 27 03 00 00 00 00 00
	Res=08 07 E8 06 67 03 45 73 20 77 00
	Req=08 07 E0 10 0A 27 04 A7 39 77 62
	Res=08 07 E8 30 00 00 00 00 00 00 00
	Req=08 07 E0 21 6D 33 40 42 00 00 00
	Res=08 07 E8 02 67 04 00 00 00 00 00

	(2)
	Req=08 07 E0 02 27 03 00 00 00 00 00
	Res=08 07 E8 06 67 03 87 02 35 54 00
	Req=08 07 E0 10 0A 27 04 13 71 01 6F
	Res=08 07 E8 30 00 00 00 00 00 00 00
	Req=08 07 E0 21 8B C2 1D D0 00 00 00
	Res=08 07 E8 02 67 04 00 00 00 00 00

	(3)
	Req=08 07 E0 02 27 03 00 00 00 00 00
	Res=08 07 E8 06 67 03 13 48 73 20 00
	Req=08 07 E0 10 0A 27 04 73 73 DE 71
	Res=08 07 E8 30 00 00 00 00 00 00 00
	Req=08 07 E0 21 1C D8 38 4E 00 00 00
	Res=08 07 E8 02 67 04 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode03(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		BYTE tmpKey[20] = { 0 };
		UINT* pTmp = (UINT*)tmpKey;
		WORD i = 0;
		while (i < strMask.GetLength())
		{
			if (i + 8 <= strMask.GetLength())
			{
				pTmp[i / 8] = StringToInt(strMask.Mid(i, 8), 16);
			}
			i += 8;
		}

		BYTE byteKey[8] = { 0 };
		i = 0;
		while (i < binRecvSeed.m_nSize && i < 8)
		{
			byteKey[i] = binRecvSeed[i];
			++i;
		}

		BYTE digist[20] = { 0 };
		BYTE pin[8] = { 0 };
		memset(pin, 0, 8);
		memcpy(pin, byteKey, 8);
		SHA1B3_CTX ctx;
		SHA1B3_Init(&ctx);
		SHA1B3_Update(&ctx, tmpKey, 16);
		SHA1B3_Update(&ctx, pin, 8);
		SHA1B3_Final(digist, &ctx);
		for (i = 0; i < 8; ++i)
		{
			binKey += (unsigned char)digist[i];
		}
	}

	/*
	(1)
	Req=82 11 F1 27 01 AC
	Res=86 F1 11 67 01 36 50 84 38 32
	Req=86 11 F1 27 02 54 68 40 50 FD
	Res=82 F1 11 67 02 ED

	(2)
	Req=82 11 F1 27 01 AC
	Res=86 F1 11 67 01 42 10 81 29 EC
	Req=86 11 F1 27 02 60 28 3D 41 B7
	Res=82 F1 11 67 02 ED

	(3)
	Req=82 11 F1 27 01 AC
	Res=86 F1 11 67 01 12 92 43 58 2F
	Req=86 11 F1 27 02 30 4D 5C 70 FA
	Res=82 F1 11 67 02 ED
	*/
	void CalcSecuAccess_Mode04(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		CBinary binMask = StringToBinary(strMask);
		if (4 != binMask.GetSize() || 4 != binRecvSeed.m_nSize)
		{
			return;
		}
		for (int i = 0; i < 4; ++i)
		{
			binKey += (BYTE)((binRecvSeed[i] - 32 + 94 * binMask[i] / 256) % 93 + 33);
		}

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	/*
	(1)
	Req=88 18 DA 00 FA 02 27 03 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 03 36 50 84 38 00
	Req=88 18 DA 00 FA 06 27 04 11 60 31 6E 00
	Res=88 18 DA FA 00 03 67 04 00 00 00 00 00

	(2)
	Req=88 18 DA 00 FA 02 27 03 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 03 06 20 32 68 00
	Req=88 18 DA 00 FA 06 27 04 21 10 80 30 00
	Res=88 18 DA FA 00 03 67 04 00 00 00 00 00

	(3)
	Req=88 18 DA 00 FA 02 27 03 00 00 00 00 00
	Res=88 18 DA FA 00 06 67 03 85 18 34 77 00
	Req=88 18 DA 00 FA 06 27 04 3F 04 C2 D3 00
	Res=88 18 DA FA 00 03 67 04 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode05(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 8);
		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);

		UINT count = (nSeed & 0xF0000) >> 16;
		UINT tmp1 = nSeed;
		UINT tmp2 = nSeed;
		UINT pos = (nSeed & 0x30) >> 4;
		UINT flag = nSeed & 8;
		for (UINT i = 0; i < count && (nSeed & 7) != 5; ++i)
		{
			if (flag)
			{
				tmp1 >>= 1;
				tmp2 <<= 0x1F;
			}
			else
			{
				tmp1 <<= 1;
				tmp2 >>= 0x1F;
			}
			tmp1 |= tmp2;
			nSeed = tmp1;
			tmp2 = tmp1;
		}

		UINT nKey = nSeed ^ groupMask[pos];
		binKey = GetSecurityAccessKey(nKey, 4);
	}

	void CalcSecuAccess_Mode06(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 8);
		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);

		UINT crc = 0;
		UINT count = 0;

		for (int i = 0; (i < 16) && (i < groupMask.GetSize()); ++i)
		{
			if (nSeed & 1)
			{
				crc ^= groupMask[i + 1];
				nSeed >>= 1;
				++count;
			}
			else
			{
				nSeed >>= 1;
			}
		}
		if (!(count & 1))
		{
			crc ^= groupMask[0];
		}

		unsigned short w3 = binRecvSeed[0] & 0xF;
		unsigned short w2 = binRecvSeed[1] & 0xF0;

		if (binRecvSeed[0] >= 0xBF)
		{
			crc += 256;
		}

		int tmp = crc >> 8;
		if (w3 == 0xF)
		{
			crc -= 4;
			crc += tmp << 8;
		}
		if (w3 == 11)
		{
			crc = (crc & 0xF0) + 3;
			crc = crc + (tmp << 8);
		}
		if (w3 == 3)
			crc = (crc & 0xF0) + 0xB + (tmp << 8);
		if (w2 >= 0xB0)
			crc--;

		binKey = GetSecurityAccessKey(crc, 2);
	}

	/*
	(1)  //346
	Req=08 07 E0 02 27 01 00 00 00 00 00
	Res=08 07 E8 06 67 01 53 55 46 16 00
	Req=08 07 E0 06 27 02 A6 EB C9 50 00
	Res=08 07 E8 03 67 02 00 00 00 00 00

	(2)
	Req=08 07 E0 02 27 01 00 00 00 00 00
	Res=08 07 E8 06 67 01 97 53 73 42 00
	Req=08 07 E0 06 27 02 21 11 79 E6 00
	Res=08 07 E8 03 67 02 00 00 00 00 00

	(3)
	Req=08 07 E0 02 27 01 00 00 00 00 00
	Res=08 07 E8 06 67 01 23 78 46 92 00
	Req=08 07 E0 06 27 02 51 50 22 6C 00
	Res=08 07 E8 03 67 02 00 00 00 00 00
	*/
	void CalcSecuAccess_Mode07(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 8);
		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);
		UINT nKey = 0x00;
		UINT count = 0;

		unsigned short w3 = nSeed & 0xFFFF;
		unsigned short w2 = nSeed & 0xFF00FF;
		unsigned short w1 = nSeed & 0xFF0000FF;
		unsigned short w0 = nSeed & 0xFF00FF00;

		for (int i = 0; i < 32; ++i)
		{
			if (nSeed & 0x01)
			{
				nKey ^= groupMask[i + 1];
				++count;
			}
			nSeed >>= 1;
		}
		if (!(count & 0x01))
		{
			nKey ^= groupMask[0];
		}

		if (!w3 || !w2 || !w1 || !w0)
			nKey = GetSecurityAccessSeed(binRecvSeed) * 0x33A;

		binKey = GetSecurityAccessKey(nKey, 4);
	}

	//新增日野电装国四CAN的安全访问模式。Add by zhoubaoshun 20200907
	void CalcSecuAccess_Mode08(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		binKey.Empty();
		for (WORD i = 0; i < binRecvSeed.m_nSize; ++i)
		{
			binKey += ~binRecvSeed[i];
		}

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode09(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 4);

		if (16 != groupMask.size())
		{
			return;
		}

		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);
		UINT nKey = 0x00;

		for (WORD i = 0; i < groupMask.size(); ++i)
		{
			if (nSeed & (0x01 << i))
			{
				nKey ^= groupMask[i];
			}
		}

		binKey = GetSecurityAccessKey(nKey, 2);
	}

	void CalcSecuAccess_Mode0A(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 8);

		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);
		UINT nKey = 0x00;
		UINT nInput[4] = { 0 };

		nInput[0] = nSeed;
		nInput[3] = (nInput[0] & 0xF0000) >> 16;
		nInput[1] = (nInput[0] & 0x30) >> 4;
		nInput[2] = nInput[0] & 0x08;
		nKey = nInput[0];

		for (UINT j = 0; j < nInput[3] && (nInput[0] & 7) != 5; ++j)
		{
			if (nInput[2])
			{
				nInput[0] = (nKey >> 1) | (nKey << 31) & 0x80000000;
			}
			else
			{
				nInput[0] = 2 * nKey & 0xFFFFFFFE | (nKey >> 31);
			}
			nKey = nInput[0];
		}
		nKey = nInput[0] ^ groupMask[nInput[1]];
		binKey = GetSecurityAccessKey(nKey, 4);
	}

	void CalcSecuAccess_Mode0B(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 8);

		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);
		UINT nKey = 0x00;
		UINT count = 0;

		unsigned short w3 = nSeed & 0xFFFF;
		unsigned short w2 = nSeed & 0xFF00FF;
		unsigned short w1 = nSeed & 0xFF0000FF;
		unsigned short w0 = nSeed & 0xFF00FF00;

		for (int i = 0; i < 32; ++i)
		{
			if (nSeed & 1)
			{
				nKey ^= groupMask[i + 1];
				++count;
			}
			nSeed >>= 1;
		}
		if (!(count & 1))
			nKey ^= groupMask[0];

		if (!w3 || !w2 || !w1 || !w0)
			nKey = 0x56837204;
		binKey = GetSecurityAccessKey(nKey, 4);
	}

	void CalcSecuAccess_Mode0C(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 2);
		binKey = CBinary(4);
		binKey[0] = ((((binRecvSeed[1] << groupMask[0] % 8) & 0xFF00) >> 8) | (binRecvSeed[1] << groupMask[0] % 8) & 0xFF) ^ groupMask[0];
		binKey[1] = ((((binRecvSeed[3] << groupMask[1] % 8) & 0xFF00) >> 8) | (binRecvSeed[3] << groupMask[1] % 8) & 0xFF) ^ groupMask[1];
		binKey[2] = ((((binRecvSeed[0] << groupMask[2] % 8) & 0xFF00) >> 8) | (binRecvSeed[0] << groupMask[2] % 8) & 0xFF) ^ groupMask[2];
		binKey[3] = ((((binRecvSeed[2] << groupMask[3] % 8) & 0xFF00) >> 8) | (binRecvSeed[2] << groupMask[3] % 8) & 0xFF) ^ groupMask[3];
	
#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode0D(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 2);
		binKey = CBinary(4);
		for (WORD i = 0; i < 4 && i < binRecvSeed.m_nSize; ++i)
			binKey[i] = binRecvSeed[i];

		for (int j = 35; j > 0; --j)
		{
			int v6 = 0;
			for (int k = 4; k > 0; --k)
			{
				if (v6)
				{
					v6 = (binKey[k - 1] & 0x80) >> 7;
					binKey[k - 1] = (2 * binKey[k - 1] & 0xFF) + 1;
				}
				else
				{
					v6 = (binKey[k - 1] & 0x80) >> 7;
					binKey[k - 1] = 2 * binKey[k - 1] & 0xFF;
				}
			}
			if (v6)
			{
				for (int k = 0; k < 4; ++k)
					binKey[k] ^= groupMask[k];
			}
		}

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode0E(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 2);
		binKey = CBinary(4);
		for (WORD i = 0; i < 4 && i < binRecvSeed.m_nSize; ++i)
			binKey[i] = binRecvSeed[i];
		int count = 35;
		while (count > 0)
		{
			UINT crc = 0;
			for (int i = 4; i > 0; --i)
			{
				if (crc)
				{
					crc = (binKey[i - 1] & 0x80u) >> 7;
					binKey[i - 1] = 2 * binKey[i - 1] + 1;
				}
				else
				{
					crc = (binKey[i - 1] & 0x80u) >> 7;
					binKey[i - 1] *= 2;
				}
			}
			if (crc)
			{
				for (int i = 0; i < 4; ++i)
					binKey[i] ^= (groupMask[i] & 0xFF);
			}
			count--;
		}

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode0F(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 2);
		UINT iInput[4] = { 0 };
		UINT crc[2] = { 0 };
		UINT count = 0;
		for (int i = 0; i < 4; ++i)
		{
			if (i + 4 < binRecvSeed.m_nSize)
			{
				groupMask[i] = binRecvSeed[i + 4];
			}
			else
			{
				groupMask[i] = 0x00;
			}
		}
		crc[1] = GetSecurityAccessSeed(binRecvSeed);
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif
		iInput[3] = (BYTE)(~binRecvSeed[0]);
		iInput[2] = (BYTE)(~binRecvSeed[1]);
		iInput[1] = (BYTE)(~binRecvSeed[2]);
		iInput[0] = (BYTE)(~binRecvSeed[3]);
		crc[0] = (iInput[3] << 24) + (iInput[2] << 16) + (iInput[1] << 8) + iInput[0];
		for (int nn = 0; nn < 2; ++nn)
		{
			crc[1] += ((16 * crc[0] ^ (crc[0] >> 5)) + crc[0]) ^ (count + groupMask[count & 3]);
			count += 0x9E3779B9;
			crc[0] += ((16 * crc[1] ^ (crc[1] >> 5)) + crc[1]) ^ (count + groupMask[((unsigned int)count >> 11) & 3]);
		}
		binKey = CBinary(4);
		for (int i = 0; i < 4; ++i)
			binKey[i] = crc[1] >> 8 * (3 - i);

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode10(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 8);
		UINT nSeed = GetSecurityAccessSeed(binRecvSeed);
		UINT nKey = 0x00;
		UINT count = 0;

		UINT u1 = nSeed & 0xFFFF;
		UINT u2 = nSeed & 0xFF00FF;
		UINT u3 = nSeed & 0xFF0000FF;
		UINT u4 = nSeed & 0xFF00FF00;

		for (int i = 0; i < 32; ++i)
		{
			if (nSeed & 1)
			{
				nKey ^= groupMask[i + 1];
				++count;
			}
			nSeed >>= 1;
		}
		if (!(count & 1))
			nKey ^= groupMask[0];
		if (!u1 || !u2 || !u3 || !u4)
			nKey = 0x54839204;

		binKey = GetSecurityAccessKey(nKey, 4);
	}

	void CalcSecuAccess_Mode11(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{


		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 2);
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif
		binKey = CBinary(4);
		groupMask[0] ^= (binRecvSeed[1] >> (8 - (groupMask[0] & 7))) | (binRecvSeed[1] << (groupMask[0] & 7));
		groupMask[1] ^= (binRecvSeed[3] >> (8 - (groupMask[1] & 7))) | (binRecvSeed[3] << (groupMask[1] & 7));
		groupMask[2] ^= (binRecvSeed[0] >> (8 - (groupMask[2] & 7))) | (binRecvSeed[0] << (groupMask[2] & 7));
		groupMask[3] ^= (binRecvSeed[2] >> (8 - (groupMask[3] & 7))) | (binRecvSeed[2] << (groupMask[3] & 7));
		for (int i = 0; i < 4; ++i)
		{
			binKey[i] = groupMask[i];
		}

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode12(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		UINT base = binRecvSeed[0] << 8 | binRecvSeed[1];
		base = base ^ 8 * (base ^ (base >> 2));
		binKey += (base >> 8) & 0xFF;
		binKey += base & 0xFF;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode13(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		int temp = input;
		int i = 0;
		while (i < 0x23)
		{
			if (temp >= 0)
				temp *= 2;
			else
				temp = 2 * temp ^ 0x616C616C;
			++i;
		}
		if (!(temp >> 24) || !(temp >> 16) & 0xFF || !(temp >> 8) & 0xFF || !(temp & 0xFF))
			temp = 0x453EF109;
		for (int k = 0; k < 4; k++)
		{
			binKey += temp >> 8 * (3 - k);
		}

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode14(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		CGroup<UINT> groupMask = GetSecurityAccessMask(strMask, 4);
		binKey = CBinary(4);
		UINT nKey = 0x00;
		if (binRecvSeed.m_nSize < 4)
		{
			nKey = 0xFABA659B;
		}
		else
		{
			UINT nSeed = GetSecurityAccessSeed(binRecvSeed);
			WORD nCount = (binRecvSeed[1] & 0x0f); //旋转次数
			WORD nMaskNum = (binRecvSeed[3] >> 4) & 0x03; //掩码号
			WORD nDirection = (binRecvSeed[3] >> 3) & 0x01; //旋转方向
			do 
			{
				if (!nCount)
				{
					nKey = nSeed ^ groupMask[nMaskNum];
				}
				else
				{
					if (0x05 == (nSeed & 0x07))
					{
						nKey = nSeed ^ groupMask[nMaskNum];
					}
					else
					{
						if (nDirection)
						{
							if (nSeed & 0x01)
							{
								nSeed = (nSeed >> 1) + 0x80000000;
							}
							else
							{
								nSeed >>= 1;
							}
						}
						else
						{
							if ((nSeed >> 24) & 0x80)
							{
								nSeed = (nSeed << 1) + 0x01;
							}
							else
							{
								nSeed <<= 1;
							}
						}
						--nCount;
					}
				}
			} while (nCount);
		}

		binKey = GetSecurityAccessKey(nKey, 4);
	}

	unsigned char BYTE3(int x)
	{
		return (unsigned char)(x >> 24 & 0xFF);
	}

	void CalcSecuAccess_Mode15(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		int arr0[] = { 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4 };
		int arr1[] = { 6, 7, 4, 5, 2, 3, 0, 1, 14, 15, 12, 13, 10, 11, 9, 8 };
		int arr2[] = { 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10 };
		int arr3[] = { 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5 };
		int arr4[] = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
		int arr5[] = { 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5 };
		int arr6[] = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
		int arr7[] = { 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4 };
		int arr8[] = { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };
		int arr9[] = { 10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5 };
		int arr10[] = { 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14 };
		int arr11[] = { 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0, 3, 2 };
		int arr12[] = { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };
		int arr13[] = { 14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1 };
		int arr14[] = { 9, 8, 11, 10, 13, 12, 15, 14, 1, 0, 3, 2, 5, 4, 7, 6 };
		int arr15[] = { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
		int arr16[] = { 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7 };
		int arr17[] = { 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 6, 7, 1, 0, 3, 2 };
		int arr18[] = { 5, 4, 7, 6, 1, 0, 3, 2, 13, 12, 15, 14, 9, 8, 11, 10 };
		int arr19[] = { 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13 };

		int v2_9;
		int v19[0x10] = { 0 };
		int v20[0x10] = { 0 };
		int v21[0x10] = { 0 };
		int v22[0x10] = { 0 };
		int v23[0x10] = { 0 };
		int v24[0x10] = { 0 };
		int v25[0x10] = { 0 };
		int v26[0x10] = { 0 };
		int v27[0x10] = { 0 };
		int v28[0x10] = { 0 };
		int v29[0x10] = { 0 };
		int v30[0x90] = { 0 };
		int v30_48[0x10] = { 0 };
		//unsigned char *binKey = seed;
		memcpy((v30 + 0x80), arr0, 0x10 * sizeof(int));
		memcpy((v30 + 0x70), arr1, 0x10 * sizeof(int));
		memcpy((v30 + 0x60), arr2, 0x10 * sizeof(int));
		memcpy((v30 + 0x50), arr3, 0x10 * sizeof(int));
		memcpy((v30 + 0x40), arr4, 0x10 * sizeof(int));
		memcpy((v30 + 0x30), arr5, 0x10 * sizeof(int));
		memcpy((v30 + 0x20), arr6, 0x10 * sizeof(int));
		memcpy((v30 + 0x10), arr7, 0x10 * sizeof(int));
		memcpy(v30, arr8, 0x10 * sizeof(int));
		memcpy(v29, arr9, 0x10 * sizeof(int));
		memcpy(v28, arr10, 0x10 * sizeof(int));
		memcpy(v27, arr11, 0x10 * sizeof(int));
		memcpy(v26, arr12, 0x10 * sizeof(int));
		memcpy(v25, arr13, 0x10 * sizeof(int));
		memcpy(v24, arr14, 0x10 * sizeof(int));
		memcpy(v23, arr15, 0x10 * sizeof(int));
		memcpy(v22, arr16, 0x10 * sizeof(int));
		memcpy(v21, arr17, 0x10 * sizeof(int));
		memcpy(v20, arr18, 0x10 * sizeof(int));
		memcpy(v19, arr19, 0x10 * sizeof(int));
		memcpy(v30_48, v30 + 0x30, 0x10 * sizeof(int));

		int binKeyint = (binRecvSeed[3] & 0xFF) << 24 | (binRecvSeed[0] & 0xFF | (binRecvSeed[1] & 0xFF) << 8 | (binRecvSeed[2] & 0xFF) << 16);
		int u2 = binRecvSeed[3] & 0xFF | (binRecvSeed[2] & 0xFF) << 8 | (binRecvSeed[1] & 0xFF) << 16 | (binRecvSeed[0] & 0xFF) << 24;
		int u3 = BYTE3(binKeyint) & 0xF0;
		int v4 = BYTE3(binKeyint) & 15;
		long v27_ = 0xFFFFFFFFL;
		binKey = CBinary(4);
		if (u3 == 0x70) {
			int u10 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] - 0x70 & 0xFF;
			int u11 = u10 & 0xFFFF00FF | v21[((int)(((((long)u10) & v27_) << 16 & v27_) >> 28))] * 16 + v30[((int)(((((long)u10) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
			int u6 = 0xFF00FFFF & u11 | v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 28))] * 16 + v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 24 & 15L)) + 0x80] << 16 & 0xFFFFFF;
			int v12 = v20[((int)((((long)u6) & v27_) >> 28))] * 16 + v19[u6 >> 24 & 15] << 24;
			int v13 = u6 & 0xFFFFFF | v12;
			binKey[0] = (unsigned char)(v12 >> 24);
			binKey[1] = (unsigned char)(v13 >> 16);
			binKey[3] = (unsigned char)v13;
			binKey[2] = (unsigned char)(v13 >> 8);
			return ;
		}
		int v31[0x10] = { 0 };
		int v32[0x10] = { 0 };
		int v33[0x10] = { 0 };
		int v34[0x10] = { 0 };
		int v35[0x10] = { 0 };
		memcpy(v31, v22, sizeof(v22));
		memcpy(v32, v22, sizeof(v23));
		memcpy(v33, v22, sizeof(v24));
		memcpy(v34, v22, sizeof(v25));
		memcpy(v35, v22, sizeof(v26));
		if (u3 <= 0x70) {
			if (u3 != 0x30) {
				if (u3 > 0x30) {
					goto label_405;
				}

				if (u3 == 16) {
					int u18 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] - 0x20 & 0xFF;
					int u15 = v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 28)) + 16] * 16 + v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF | u18 & 0xFFFF00FF;
					int u6 = 0xFF00FFFF & u15 | v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 28))] * 16 + v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
					int v12 = v27[u6 >> 24 & 15] + v28[((int)((((long)u6) & v27_) >> 28))] * 16 << 24;
					int v13 = u6 & 0xFFFFFF | v12;
					binKey[0] = (unsigned char)(v12 >> 24);
					binKey[1] = (unsigned char)(v13 >> 16);
					binKey[3] = (unsigned char)v13;
					binKey[2] = (unsigned char)(v13 >> 8);
					return ;
				}

				if (u3 == 0x20) {
					int u17 = u2 & 0xFFFFFF00 | v35[v4] - 0x70 & 0xFF;
					int u16 = u17 & 0xFFFF00FF | v30[((int)(((((long)u17) & v27_) << 16 & v27_) >> 28))] * 16 + v34[((int)(((((long)u17) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
					int u6 = 0xFF00FFFF & u16 | v33[((int)(((((long)u16) & v27_) << 8 & v27_) >> 28))] * 16 + v32[((int)(((((long)u16) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
					int v7_2 = v31[u6 >> 24 & 15] + v30[((int)((((long)u6) & v27_) >> 28)) + 80] * 16 << 24;
					int v8_2 = u6 & 0xFFFFFF | v7_2;
					binKey[0] = (unsigned char)(v7_2 >> 24);
					binKey[1] = (unsigned char)(v8_2 >> 16);
					binKey[3] = (unsigned char)v8_2;
					binKey[2] = (unsigned char)(v8_2 >> 8);
					return ;
				}

				if ((BYTE3(binKeyint) & 0xF0) == 0) {
					u2 = u2 & 0xFFFFFF00 | v30[v4 + 0x80] - 0x70 & 0xFF;
					goto label_586;
				label_405:
					if (u3 == 80) {
						int u18 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] - 0x60 & 0xFF;
						int u15 = u18 & 0xFFFF00FF | v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 28)) + 16] * 16 + v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
						int u6 = 0xFF00FFFF & u15 | v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 28))] * 16 + v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
						int v7_3 = v27[u6 >> 24 & 15] + v28[((int)((((long)u6) & v27_) >> 28))] * 16 << 24;
						int v8_3 = u6 & 0xFFFFFF | v7_3;
						binKey[0] = (unsigned char)(v7_3 >> 24);
						binKey[1] = (unsigned char)(v8_3 >> 16);
						binKey[3] = (unsigned char)v8_3;
						binKey[2] = (unsigned char)(v8_3 >> 8);
						return ;
					}

					if (u3 == 0x60) {
						int u17 = u2 & 0xFFFFFF00 | v35[v4] - 0x30 & 0xFF;
						int u16 = u17 & 0xFFFF00FF | v30[((int)(((((long)u17) & v27_) << 16 & v27_) >> 28))] * 16 + v34[((int)(((((long)u17) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
						int v2_4 = 0xFF00FFFF & u16 | v33[((int)(((((long)u16) & v27_) << 8 & v27_) >> 28))] * 16 + v32[((int)(((((long)u16) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
						int v7_4 = v31[v2_4 >> 24 & 15] + v30[((int)((((long)v2_4) & v27_) >> 28)) + 80] * 16 << 24;
						int v8_4 = v2_4 & 0xFFFFFF | v7_4;
						binKey[0] = (unsigned char)(v7_4 >> 24);
						binKey[1] = (unsigned char)(v8_4 >> 16);
						binKey[3] = (unsigned char)v8_4;
						binKey[2] = (unsigned char)(v8_4 >> 8);
						return ;
					}

					if (u3 == 0x40) {
						u2 = u2 & 0xFFFFFF00 | v30[v4 + 0x80] - 0x30 & 0xFF;
					}
				}

			label_586:
				int u5 = u2 & 0xFFFF00FF | v30[((int)(((((long)u2) & v27_) << 16 & v27_) >> 28)) + 0x70] * 16 + v30[((int)(((((long)u2) & v27_) << 16 & v27_) >> 24 & 15L)) + 0x60] << 8 & 0xFFFF;
				int u6 = 0xFF00FFFF & u5 | v30[((int)(((((long)u5) & v27_) << 8 & v27_) >> 28)) + 0x80] * 16 + v30[((int)(((((long)u5) & v27_) << 8 & v27_) >> 24 & 15L)) + 80] << 16 & 0xFFFFFF;
				int v12 = v30_48[u6 >> 24 & 15] + v30[((int)((((long)u6) & v27_) >> 28)) + 0x40] * 16 << 24;
				int v13 = u6 & 0xFFFFFF | v12;
				binKey[0] = (unsigned char)(v12 >> 24);
				binKey[1] = (unsigned char)(v13 >> 16);
				binKey[3] = (unsigned char)v13;
				binKey[2] = (unsigned char)(v13 >> 8);
				return ;
			}

			int u10 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] - 0x70 & 0xFF;
			int u11 = u10 & 0xFFFF00FF | v21[((int)(((((long)u10) & v27_) << 16 & v27_) >> 28))] * 16 + v30[((int)(((((long)u10) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
			int u6 = 0xFF00FFFF & u11 | v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 28))] * 16 + v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 24 & 15L)) + 0x80] << 16 & 0xFFFFFF;
			int v12 = v19[u6 >> 24 & 15] + v20[((int)((((long)u6) & v27_) >> 28))] * 16 << 24;
			int v13 = u6 & 0xFFFFFF | v12;
			binKey[0] = (unsigned char)(v12 >> 24);
			binKey[1] = (unsigned char)(v13 >> 16);
			binKey[3] = (unsigned char)v13;
			binKey[2] = (unsigned char)(v13 >> 8);
			return ;
		}

		int v38[0x10] = { 0 };
		int v39[0x10] = { 0 };
		memcpy(v38, v19, sizeof(v19));
		memcpy(v39, v20, sizeof(v20));
		if (u3 == 0xB0) {
			int u10 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] - 0x70 & 0xFF;
			int u11 = u10 & 0xFFFF00FF | v21[((int)(((((long)u10) & v27_) << 16 & v27_) >> 28))] * 16 + v30[((int)(((((long)u10) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
			int u6 = 0xFF00FFFF & u11 | v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 28))] * 16 + v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 24 & 15L)) + 0x80] << 16 & 0xFFFFFF;
			int v7_7 = v38[u6 >> 24 & 15] + v39[((int)((((long)u6) & v27_) >> 28))] * 16 << 24;
			int v8_6 = u6 & 0xFFFFFF | v7_7;
			binKey[0] = (unsigned char)(v7_7 >> 24);
			binKey[1] = (unsigned char)(v8_6 >> 16);
			binKey[3] = (unsigned char)v8_6;
			binKey[2] = (unsigned char)(v8_6 >> 8);
			return ;
		}

		if (u3 <= 0xB0) {
			if (u3 == 0x90) {
				int u18 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] + 0x60 & 0xFF;
				int u15 = u18 & 0xFFFF00FF | v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 28)) + 16] * 16 + v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
				int v2_7 = 0xFF00FFFF & u15 | v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 28))] * 16 + v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
				int v7_8 = v27[v2_7 >> 24 & 15] + v28[((int)((((long)v2_7) & v27_) >> 28))] * 16 << 24;
				int v8_7 = v2_7 & 0xFFFFFF | v7_8;
				binKey[0] = (unsigned char)(v7_8 >> 24);
				binKey[1] = (unsigned char)(v8_7 >> 16);
				binKey[3] = (unsigned char)v8_7;
				binKey[2] = (unsigned char)(v8_7 >> 8);
				return ;
			}

			if (u3 == 0xA0) {
				int u17 = u2 & 0xFFFFFF00 | v35[v4] + 16 & 0xFF;
				int u16 = u17 & 0xFFFF00FF | v30[((int)(((((long)u17) & v27_) << 16 & v27_) >> 28))] * 16 + v34[((int)(((((long)u17) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
				int v2_8 = 0xFF00FFFF & u16 | v33[((int)(((((long)u16) & v27_) << 8 & v27_) >> 28))] * 16 + v32[((int)(((((long)u16) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
				int v7_9 = v31[v2_8 >> 24 & 15] + v30[((int)((((long)v2_8) & v27_) >> 28)) + 80] * 16 << 24;
				int v8_8 = v2_8 & 0xFFFFFF | v7_9;
				binKey[0] = (unsigned char)(v7_9 >> 24);
				binKey[1] = (unsigned char)(v8_8 >> 16);
				binKey[3] = (unsigned char)v8_8;
				binKey[2] = (unsigned char)(v8_8 >> 8);
				return ;
			}

			if (u3 == 0x80) {
				v2_9 = 16;
				u2 = u2 & 0xFFFFFF00 | v30[v4 + 0x80] + 16 & 0xFF;
			}
			else {
				v2_9 = 16;
			}

			int u5 = u2 & 0xFFFF00FF | v30[((int)(((((long)u2) & v27_) << v2_9 & v27_) >> 28)) + 0x70] * 16 + v30[((int)(((((long)u2) & v27_) << v2_9 & v27_) >> 24 & 15L)) + 0x60] << 8 & 0xFFFF;
			int u6 = 0xFF00FFFF & u5 | v30[((int)(((((long)u5) & v27_) << 8 & v27_) >> 28)) + 0x80] * 16 + v30[((int)(((((long)u5) & v27_) << 8 & v27_) >> 24 & 15L)) + 80] << 16 & 0xFFFFFF;
			int v12 = v30_48[u6 >> 24 & 15] + v30[((int)((((long)u6) & v27_) >> 28)) + 0x40] * 16 << 24;
			int v13 = u6 & 0xFFFFFF | v12;
			binKey[0] = (unsigned char)(v12 >> 24);
			binKey[1] = (unsigned char)(v13 >> 16);
			binKey[3] = (unsigned char)v13;
			binKey[2] = (unsigned char)(v13 >> 8);
			return ;
		}

		if (u3 == 0xD0) {
			int u18 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] + 0x20 & 0xFF;
			int u15 = u18 & 0xFFFF00FF | v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 28)) + 16] * 16 + v30[((int)(((((long)u18) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
			int u6 = 0xFF00FFFF & u15 | v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 28))] * 16 + v29[((int)(((((long)u15) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
			int v12 = v27[u6 >> 24 & 15] + v28[((int)((((long)u6) & v27_) >> 28))] * 16 << 24;
			int v13 = u6 & 0xFFFFFF | v12;
			binKey[0] = (unsigned char)(v12 >> 24);
			binKey[1] = (unsigned char)(v13 >> 16);
			binKey[3] = (unsigned char)v13;
			binKey[2] = (unsigned char)(v13 >> 8);
			return ;
		}

		if (u3 > 0xD0) {
			if (u3 == 0xE0) {
				int u17 = u2 & 0xFFFFFF00 | v35[v4] + 80 & 0xFF;
				int u16 = u17 & 0xFFFF00FF | v30[((int)(((((long)u17) & v27_) << 16 & v27_) >> 28))] * 16 + v34[((int)(((((long)u17) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
				int v2_11 = 0xFF00FFFF & u16 | v33[((int)(((((long)u16) & v27_) << 8 & v27_) >> 28))] * 16 + v32[((int)(((((long)u16) & v27_) << 8 & v27_) >> 24)) & 15] << 16 & 0xFFFFFF;
				int v7_12 = v31[v2_11 >> 24 & 15] + v30[((int)((((long)v2_11) & v27_) >> 28)) + 80] * 16 << 24;
				int v8_10 = v2_11 & 0xFFFFFF | v7_12;
				binKey[0] = (unsigned char)(v7_12 >> 24);
				binKey[1] = (unsigned char)(v8_10 >> 16);
				binKey[3] = (unsigned char)v8_10;
				binKey[2] = (unsigned char)(v8_10 >> 8);
				return ;
			}

			if (u3 == 0xF0) {
				int u10 = u2 & 0xFFFFFF00 | v30[v4 + 0x20] - 0x70 & 0xFF;
				int u11 = u10 & 0xFFFF00FF | v21[((int)(((((long)u10) & v27_) << 16 & v27_) >> 28))] * 16 + v30[((int)(((((long)u10) & v27_) << 16 & v27_) >> 24)) & 15] << 8 & 0xFFFF;
				int v2_12 = 0xFF00FFFF & u11 | v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 28))] * 16 + v30[((int)(((((long)u11) & v27_) << 8 & v27_) >> 24 & 15L)) + 0x80] << 16 & 0xFFFFFF;
				int v7_13 = v38[v2_12 >> 24 & 15] + v39[((int)((((long)v2_12) & v27_) >> 28))] * 16 << 24;
				int v8_11 = v2_12 & 0xFFFFFF | v7_13;
				binKey[0] = (unsigned char)(v7_13 >> 24);
				binKey[1] = (unsigned char)(v8_11 >> 16);
				binKey[3] = (unsigned char)v8_11;
				binKey[2] = (unsigned char)(v8_11 >> 8);
				return ;
			}
		}
		else if (u3 == 0xC0) {
			u2 = u2 & 0xFFFFFF00 | v30[v4 + 0x80] + 80 & 0xFF;
		}

		int u5 = u2 & 0xFFFF00FF | v30[((int)(((((long)u2) & v27_) << 16 & v27_) >> 28)) + 0x70] * 16 + v30[((int)(((((long)u2) & v27_) << 16 & v27_) >> 24 & 15L)) + 0x60] << 8 & 0xFFFF;
		int u6 = 0xFF00FFFF & u5 | v30[((int)(((((long)u5) & v27_) << 8 & v27_) >> 28)) + 0x80] * 16 + v30[((int)(((((long)u5) & v27_) << 8 & v27_) >> 24 & 15L)) + 80] << 16 & 0xFFFFFF;
		int v12 = v30_48[u6 >> 24 & 15] + v30[((int)((((long)u6) & v27_) >> 28)) + 0x40] * 16 << 24;
		int v13 = u6 & 0xFFFFFF | v12;
		binKey[0] = (unsigned char)(v12 >> 24);
		binKey[1] = (unsigned char)(v13 >> 16);
		binKey[3] = (unsigned char)v13;
		binKey[2] = (unsigned char)(v13 >> 8);

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
		return ;
	}

	void CalcSecuAccess_Mode16(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		binKey = CBinary(4);
		unsigned char binSeed[4] = { binRecvSeed[0],binRecvSeed[1],binRecvSeed[2],binRecvSeed[3] };
		unsigned char* v2;
		unsigned char* v3;
		unsigned int v4;
		unsigned int v5;
		unsigned int v6;

		v2 = binSeed - 1;
		v3 = binSeed + 3;
		v4 = 0xFFFF;
		do
		{
			v5 = (unsigned char)*++v2;
			v4 ^= v5;
			v6 = 8;
			do
			{
				if ((v4 & 1) != 0)
					v4 = (v4 >> 1) ^ 0xA001;
				else
					v4 >>= 1;
				--v6;
			} while (v6);
		} while (v2 != v3);
		binKey[3] = 0;
		binKey[0] = ((v4 >> 8) | 0xB1) & 0xFF;
		binKey[2] = ((((unsigned char)v4 << 16) + 689) | (v4 >> 8)) >> 16;
		binKey[1] = 2;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
		return;
	}

	//Add by zkh -2021-4-20:N800HP国六	车身控制模块(BCM)	hdjljmc/jl136 /  hdjljmc/jl135  /  hdjljmc/jl137
	void CalcSecuAccess_Mode17(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		binKey = CBinary("\x00\x00\x00\x00", 4);
		INT input = (binRecvSeed[0]<<24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		for (int i = 0; i < 35; ++i)
		{
			if (input >= 0)
				input = (2 * input) & ~(input >> 0x1F);
			else
			{
				input *= 2;
				input ^= StringToInt(strMask , 16);
			}
		}
		binKey[0] = (input >> 24) & 0xFF;
		binKey[1] = (input >> 16) & 0xFF;
		binKey[2] = (input >> 8) & 0xFF;
		binKey[3] = input & 0xFF;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	//Add by zkh -2021-4-20:N800HP国六	万安气制动ABS	hdjljmc/jl131
	void CalcSecuAccess_Mode18(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif

		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		UINT crc = (8 * (input ^ (input >> 2))) ^ StringToInt(strMask , 16);

		binKey[0] = (crc >> 24) & 0xFF;
		binKey[1] = (crc >> 16) & 0xFF;
		binKey[2] = (crc >> 8) & 0xFF;
		binKey[3] = crc & 0xFF;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode19(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey) //Add by zkh : 2021-4-21:添加江西五十铃发动机系统的安全算法
	{
		WORD i = 0;
		CBinary binKeyValue;
		if (strMask == "00")
		{
			binKeyValue = CBinary("\x3E\x33\x80\xD6\x2C\x80\x38\xBB\x51\xFD\x6A\x28\xF7\xC8\xCB\xF9", 16);//hd_jxisuzu/jx041
		}
		else if (strMask == "01")
		{
			binKeyValue = CBinary("\xD2\x53\x87\x49\x91\xC5\x3B\xB3\xA6\x1F\x19\x5A\x7A\xAB\xD6\x02", 16);//hdjljmc/jl169 
		}
		else if (strMask == "02")
		{
			binKeyValue = CBinary("\x1D\x57\x39\x8C\x31\xB8\x7B\xF4\xBE\x32\x8C\x1A\x27\x9B\x34\x25",16);//hd_jxisuzu/jx001
		}

		BYTE byteKey[8] = { 0 };
		i = 0;
		while (i < binRecvSeed.m_nSize && i < 8)
		{
			byteKey[i] = binRecvSeed[i];
			++i;
		}

		BYTE digist[20] = { 0 };
		BYTE pin[8] = { 0 };
		memset(pin, 0, 8);
		memcpy(pin, byteKey, 8);

		SHA1B3_CTX sha1c;
		SHA1B3_Init(&sha1c);
		SHA1B3_Update(&sha1c, binKeyValue.GetBuffer(), 16);
		if (strMask == "02")
		{
			SHA1B3_Update(&sha1c, pin, 4);
		}
		else
		{
			SHA1B3_Update(&sha1c, pin, 8);
		}
		SHA1B3_Final(digist, &sha1c);

		if (strMask == "02")
		{
			for (i = 0; i < 4; ++i)
			{
				binKey += (unsigned char)digist[i];
			}
		}
		else
		{
			for (i = 0; i < 8; ++i)
			{
				binKey += (unsigned char)digist[i];
			}
		}
		
		//memcpy(out, tmp, 8);
	}

	void CalcSecuAccess_Mode1A(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		INT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		unsigned int v4 = 0; // ST04_4
		unsigned int v5 = 0; // r7
		unsigned int v6 = 0; // r3
		unsigned int v7 = 0; // r2
		unsigned short v8 = 0; // r1
		unsigned int v9 = 0; // r2
		unsigned short v10 = 0; // r0
		unsigned int v11 = 0; // r3
		unsigned short v12 = 0; // r2
		unsigned int v13 = 0; // r3
		unsigned int v15 = 0; // r6
		unsigned int v17 = 0; // r3
		unsigned int v18 = 0; //
		unsigned short tmp = 0;

		//接收传入
		//v4 = *(UINT*)input;
		v4 = input;
		tmp = ((unsigned char)v4) | ((unsigned short)((v4 & 0xFF0000) >> 8));     // 10 | 30 00  =>  tmp = 30 10  // << 8
		v18 = tmp << 16;//?′??μ?v18??16??

		tmp = ((unsigned short)v4 >> 8) | ((unsigned short)(v4 >> 24) << 8);	//  20 | 40 00 =>  40 20
		v18 = v18 + tmp;//?′??μ?v18μí16??

						//内存20 40 10 30

		v5 = (unsigned short)(v18 >> 15);			// 30 10 * 2 = 60 20
		v6 = (unsigned short)(2 * v18);					// 30 10 40 20 *2  = 6 2 8 4  => 8 4
		v7 = (v6 ^ (v18 >> 1)) & 0x5555 ^ v6;				// 1808 A050 & 0x5555 ^ 80 40 = 80 10
		tmp = v7;				//80 10 写入低16位
		v18 = v18 & 0xFFFF0000;	//复制到v18低16位        10 80 10 30
		v18 += tmp;
		//内存 10 80 10 30

		//int16
		v8 = 4 * v7; // 40
		v9 = (v8 ^ (v18 >> 2)) & 0x3333 ^ v8;		//2040
		tmp = v9;
		v18 = v18 & 0xFFFF0000;//复制到v18低16位
		v18 += tmp;
		//		40 20 10 30
		tmp = ((unsigned short)(16 * v9) ^ (v18 >> 4)) & 0xF0F ^ (unsigned short)(16 * v9);
		//Dy×a×óò?8??
		v10 = __ROL__(tmp,  //  204     <=  400^ 03010204 & F0F ^400
			8
		);
		//v10 = 04 02      R0: 04 02


		v11 = (v5 ^ (*(unsigned int *)((char *)&v18 + 2) >> 1)) & 0x5555 ^ v5;
		tmp = v11;



		v18 = v18 & 0x0000FFFF; //复制到v18高16位
		v18 += tmp << 16;

		//40 20 20 30

		v12 = 4 * v11;
		v13 = (v12 ^ (*(unsigned int *)((char *)&v18 + 2) >> 2)) & 0x3333 ^ v12;
		tmp = v13;
		v18 = v18 & 0x0000FFFF;//复制到v18高16位
		v18 += tmp << 16;
		//40 20 80 c0

		v18 = v18 & 0xFFFF0000 + v10;		//复制到v18低16位
		v18 += v10;
		//02 04 80 c0

		tmp = ((unsigned short)(16 * v13) ^ (*(unsigned int *)((char *)&v18 + 2) >> 4)) & 0xF0F ^ (unsigned short)(16 * v13);

		v10 = __ROL__(
			tmp, //c08
			8
		);
		// v14 = 80c

		v18 = v18 & 0x0000FFFF;
		v18 += v10 << 16;
		// 02 04 0c 08

		v15 = ((unsigned char)v10 | (((unsigned char)v18 | (((v10 >> 8) | (v18 & 0xFF00)) << 8)) << 8)) ^ 0xFB752EAD; //v18 & 0xFF00

		v17 = (v4 ^ 0xFB752EAD) + v15;

		/**output = BYTE0(v17);
		*(output + 1) = BYTE1(v17);
		*(output + 2) = BYTE2(v17);
		*(output + 3) = BYTE3(v17);*/
		//memcpy(binKey, &v17, 4);
		input = v17;
		binKey[0] = (input >> 24) & 0xFF;
		binKey[1] = (input >> 16) & 0xFF;
		binKey[2] = (input >> 8) & 0xFF;
		binKey[3] = input & 0xFF;
#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode1B(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1B");
#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		//unsigned int input = ;
		//BYTE input[4] = {0x00,0x00,0x00,0x00}
		unsigned int input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		//BYTE input[] = {0x00,0x00,0x00,0x00};
		unsigned int v2 = 0; // r2
		unsigned int v3 = 0; // r3
		unsigned int v5 = 0; // r3

		//v2 = *(unsigned int*)input;
		v2 = input;
		v3 = (v2 ^ 0x7AB4604A) & 0xFFFFFF00;
		//3A844000
		v5 = v3 | ((unsigned char)input) ^ 0x4A;
		//3A84405A

		//*output = BYTE0(v5);
		//*(output+1) = BYTE1(v5);
		//*(output+2) = BYTE2(v5);
		//*(output+3) = BYTE3(v5);

		//memcpy(output, &v5, 4);
		input = v5;
		binKey[0] = (input >> 24) & 0xFF;
		binKey[1] = (input >> 16) & 0xFF;
		binKey[2] = (input >> 8) & 0xFF;
		binKey[3] = input & 0xFF;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode1C(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1C");
#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		unsigned int input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		int v2 = 0; // r3
		unsigned int v3 = 0;  // r2
		unsigned int v4 = 0;  // r0
		bool v5; // cf

		//v2 = *(UINT*)input;
		v2 = input;
		v3 = 35;
		do
		{
			v4 = v2 * 2 ^ 0x7E9DBD9E;    // FEFDFDBE
			v5 = v2 < 0;
			v2 = v2 * 2;
			if (v5)
				v2 = v4;
			--v3;
		} while (v3);

		/**output = BYTE0(v2);
		*(output + 1) = BYTE1(v2);
		*(output + 2) = BYTE2(v2);
		*(output + 3) = BYTE3(v2);*/

		//memcpy(output, &v2, 4);
		input = v2;
		binKey[0] = (input >> 24) & 0xFF;
		binKey[1] = (input >> 16) & 0xFF;
		binKey[2] = (input >> 8) & 0xFF;
		binKey[3] = input & 0xFF;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode1D(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1D");
#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		unsigned int input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		unsigned int v2 = 0; // ST00_4
		UINT v3 = 0; // r0
		UINT v4 = 0;
		//v2 = *(UINT*)input;
		v2 = input;
		v4 = ((v2 & 0xFF00) >> 8 ^ 0x38);
		v3 = (unsigned char)((v2 ^ 0x73) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v2 >> 24) ^ 0xBC) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(16 * ((v2 & 0xFF0000) >> 16 ^ 0x45) | ((((unsigned short)v2 >> 8) ^ 0x38) >> 4)) | ((unsigned char)((v2 ^ 0x73) & 0xF0 | (((v2 >> 24) ^ 0xBC) >> 4)) << 8)) << 8)) << 8);

		binKey[3] = (v2 ^ 0x73) & 0xF0;
		binKey[2] = (v3 & 0xFF00) >> 8;
		binKey[1] = (v3 & 0xFF0000) >> 16;
		binKey[0] = (v3 & 0xFF000000) >> 24;
		
#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode1E(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1E");
#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		unsigned int input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		unsigned int v2 = 0; // ST00_4
		unsigned int v3 = 0; // r0
		unsigned int v4 = 0; // r2
		unsigned int v5 = 0; // r5
		unsigned int v6 = 0; // r6
		unsigned int v7 = 0; // r3
		unsigned int v9 = 0; // r5
		BYTE Key1 = 0;
		BYTE Key2 = 0;
		BYTE Key3 = 0;
		BYTE Key4 = 0;
		if (strMask == "00")
		{
			Key1 = 0x68;
			Key2 = 0xe2;
			Key3 = 0x31;
			Key4 = 0x45;
		}
		else if (strMask == "01")
		{
			Key1 = 0x59;
			Key2 = 0xCA;
			Key3 = 0xF1;
			Key4 = 0xD4;
		}
		//v2 = *(binRecvSeed)+(*(binRecvSeed + 1) << 8) + (*(binRecvSeed + 2) << 16) + (*(binRecvSeed + 3) << 24);
		v2 = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];;
		//v3 = *(input + 1) ^ Key1;
		v3 = binRecvSeed[2] ^ Key1;
		//v3 = ((unsigned char)input) ^ Key1;
		v4 = (v2 >> 24) ^ Key2;
		v5 = ((unsigned char)v2 ^ Key3) & 0xF0;
		v6 = (unsigned char)(8 * v3);
		v7 = (unsigned char)((v3 >> 4) | 16 * (((v2 & 0xFF0000) >> 16) ^ Key4)) | ((v5 | (v4 >> 4)) << 8);
		v9 = v5 | ((((unsigned char)v6 ^ (unsigned char)(v4 >> 1)) & 0x1F ^ v6 | (v7 << 8)) << 8);

		//memcpy(output, &v9, 4);
		input = v9;
		binKey[0] = (input >> 24) & 0xFF;
		binKey[1] = (input >> 16) & 0xFF;
		binKey[2] = (input >> 8) & 0xFF;
		binKey[3] = input & 0xFF;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode1F(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
//#if (defined WIN32 && defined NDEBUG)
//		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1F");
//#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		unsigned int input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		unsigned int v2 = 0; // ST00_4
		unsigned int v3 = 0; // r0
		unsigned int v4 = 0; // r2
		unsigned int v5 = 0; // r5
		unsigned int v6 = 0; // r6
		unsigned int v7 = 0; // r3
		unsigned int v9 = 0; // r5
		BYTE Key1 = 0;
		BYTE Key2 = 0;
		BYTE Key3 = 0;
		BYTE Key4 = 0;
		if (strMask == "00")//DADC,DCDC,PDU
		{
			Key1 = 0x59;
			Key2 = 0xCA;
			Key3 = 0xF1;
			Key4 = 0xD4;
		}
		else if (strMask == "01")//MCU
		{
			Key1 = 0x59;
			Key2 = 0x43;
			Key3 = 0xee;
			Key4 = 0x36;
		}
		else if (strMask == "02")//VCU
		{
			Key1 = 0xe9;
			Key2 = 0x14;
			Key3 = 0xF1;
			Key4 = 0x18;
		}
		else if (strMask == "03")//IC
		{
			Key1 = 0xe;
			Key2 = 0xC1;
			Key3 = 0xF2;
			Key4 = 0xc5;
		}
		else if (strMask == "04")//BCM
		{
			Key1 = 0x59;
			Key2 = 0x31;
			Key3 = 0xF1;
			Key4 = 0x32;
		}
		else if (strMask == "05")//MP5
		{
			Key1 = 0xfb;
			Key2 = 0xf1;
			Key3 = 0x91;
			Key4 = 0x35;
		}
		else if (strMask == "06")//T-BOX
		{
			Key1 = 0x89;
			Key2 = 0x25;
			Key3 = 0xe1;
			Key4 = 0x57;
		}
		else if (strMask == "07")//ABS
		{
			Key1 = 0xda;
			Key2 = 0x24;
			Key3 = 0xdb;
			Key4 = 0x46;
		}

		//v2 = *(binRecvSeed)+(*(binRecvSeed + 1) << 8) + (*(binRecvSeed + 2) << 16) + (*(binRecvSeed + 3) << 24);
		v2 = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		//v3 = *(input + 1) ^ Key1;
		v3 = binRecvSeed[2] ^ Key1;
		//v3 = ((unsigned char)input) ^ Key1;
		v4 = (v2 >> 24) ^ Key2;
		v5 = ((unsigned char)v2 ^ Key3) & 0xF0;
		v6 = (unsigned char)(8 * v3);
		v7 = (unsigned char)((v3 >> 4) | 16 * (((v2 & 0xFF0000) >> 16) ^ Key4)) | ((v5 | (v4 >> 4)) << 8);
		v9 = v5 | ((((unsigned char)v6 ^ (unsigned char)(v4 >> 1)) & 0x1F ^ v6 | (v7 << 8)) << 8);

		//memcpy(output, &v9, 4);
		input = v9;
		binKey[0] = (input >> 24) & 0xFF;
		binKey[1] = (input >> 16) & 0xFF;
		binKey[2] = (input >> 8) & 0xFF;
		binKey[3] = input & 0xFF;

//#if (defined WIN32 && defined NDEBUG)
//		VMProtectEnd();
//#endif
	}

	void CalcSecuAccess_Mode20(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1E");
#endif
		binKey = CBinary("\x00\x00", 2);
		BYTE input[2] = { 0x00,0x00 };
		input[0] = binRecvSeed[0];
		input[1] = binRecvSeed[1];
		unsigned int output = 0;
		BYTE* out = (BYTE*)&output;
		out[0] = input[0] > 0xBE ? 0xC0 - input[1] : 0xBF - input[1];
		out[1] = input[1] > 0xAF ? 0xFD - input[0] : 0xFE - input[0];
		
		binKey[0] = out[0];
		binKey[1] = out[1];

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	void CalcSecuAccess_Mode21(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1E");
#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		
		BYTE v4;
		BYTE v8;
		BYTE v9;
		UINT v10;
		UINT v11;
		UINT v14;
		int i = 0;

		BYTE tab1[16] =
		{
			0x99, 0x79, 0x76, 0x01, 0x08, 0x58, 0x76, 0x01, 0x47, 0x51,
			0x56, 0x21, 0x45, 0x44, 0x66, 0x11
		};


		v4 = binRecvSeed[3];
		v8 = binRecvSeed[1] & 0xF;
		v9 = v4 & 0x8;
		v10 = *(UINT *)&tab1[((v4 >> 4) & 3) << 2];

		//v11 = _byteswap_ulong(*(UINT *)binRecvSeed);
		v11 = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];

		do
		{
			if (i < v8 && (v11 & 7) != 5)
			{
				v11 = v9 == true ? __ROR__(v11, 1) : __ROR__(v11, 31);
				continue;
			}
			break;
		} while (++i);

		v14 = v11 ^ v10;
		//out[0] = *((BYTE*)&v14 + 3);
		//out[1] = *((BYTE*)&v14 + 2);
		//out[2] = *((BYTE*)&v14 + 1);
		//out[3] = *((BYTE*)&v14 + 0);
		binKey[0] = *((BYTE*)&v14 + 3);
		binKey[1] = *((BYTE*)&v14 + 2);
		binKey[2] = *((BYTE*)&v14 + 1);
		binKey[3] = *((BYTE*)&v14 + 0);
#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif

	}

	void CalcSecuAccess_Mode22(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::CalcSecuAccess_Mode1E");
#endif
		binKey = CBinary("\x00\x00\x00\x00", 4);
		BYTE v2;
		UINT v3;
		UINT v5;

		v2 = binRecvSeed[3];
		//v3 = _byteswap_ulong(*(UINT *)in);
		v3 = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		v5 = (BYTE)((((v3 & 0xFF000000) >> 24) ^ 0xAF) << 4) | (v2 ^ 0x66) & 0xF | (((((v3 & 0xFF0000) >> 16) ^ 0x9E) & 0xF0 | ((v2 ^ 0x66) >> 4) | ((v3 & 0xFF00 ^ 0x100 | (BYTE)((((v3 & 0xFF000000) >> 24) ^ 0xAF) << 4 | (((v3 >> 16) & 0xFF ^ 0x9E) >> 4))) << 8)) << 8);

		binKey[0] = *((BYTE*)&v5 + 3);
		binKey[1] = *((BYTE*)&v5 + 2);
		binKey[2] = *((BYTE*)&v5 + 1);
		binKey[3] = *((BYTE*)&v5 + 0);
#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	CGroup<UINT> GetSecurityAccessMask(const TString& strMask, int nLen)
	{
		CGroup<UINT> groupMask;
		WORD i = 0;
		while (i < strMask.GetLength())
		{
			if ((i + nLen) <= strMask.GetLength())
			{
				groupMask.push_back(StringToInt(strMask.Mid(i, nLen), 16));
			}
			i += nLen;
		}
		return groupMask;
	}

	UINT GetSecurityAccessSeed(const CBinary& binSeed)
	{
		UINT nValue = 0x00;
		WORD nSize = binSeed.m_nSize;
		for (WORD i = 0; i < nSize; ++i)
		{
			nValue <<= 8;
			nValue += binSeed[i];
		}
		return nValue;
	}

	CBinary GetSecurityAccessKey(UINT nKey, int nLen)
	{
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("Cdfcv_security_access::SecurityAccess");
#endif
		CBinary binKey;
		for (int i = 0; i < nLen; ++i)
		{
			binKey += (BYTE)(nKey >> ((nLen - i - 1) * 8));
		}
		return binKey;

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
	}

	//江西五十铃二期开发安全算法(Add by zkh - 2021-5-20)
	//江铃--江西五十铃--瑞迈S--柴油国六--防抱死刹车系统—特殊功能
	void CalcSecuAccess_Mode2B(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		unsigned int v2 = 0; // r2
		unsigned int v3 = 0; // ST00_4
		unsigned int v5 = 0; // r2
		unsigned int v4 = 0;

		v3 = input;
		v2 = (unsigned char)v3;
		v4 = (v3 & 0xFF00) >> 8 ^ 0x37;
		v5 = (unsigned char)((v2 ^ 0x3F) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v3 >> 24) ^ 0x83) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(((((unsigned short)v3 >> 8) ^ 0x37) >> 4) | 16 * ((v3 & 0xFF0000) >> 16 ^ 0xD6)) | ((((unsigned char)v2 ^ 0x3F) & 0xF0 | (((v3 >> 24) ^ 0x83) >> 4)) << 8)) << 8)) << 8);

		binKey[0] = (v5 >> 24) & 0xFF;
		binKey[1] = (v5 >> 16) & 0xFF;
		binKey[2] = (v5 >> 8) & 0xFF;
		binKey[3] = v5 & 0xFF;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--空调系统—动作测试/特殊功能
	void CalcSecuAccess_Mode2C(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		unsigned int v2 = 0; // ST00_4
		unsigned int v3 = 0; // r0
		unsigned int v4 = 0;

		v2 = input;
		v4 = (v2 & 0xFF00) >> 8 ^ 6;
		v3 = (unsigned char)((v2 ^ 0xF5) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v2 >> 24) ^ 0x6D) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(16 * ((v2 & 0xFF0000) >> 16 ^ 0xA7) | ((((unsigned short)v2 >> 8) ^ 6) >> 4)) | ((unsigned char)((v2 ^ 0xF5) & 0xF0 | (((v2 >> 24) ^ 0x6D) >> 4)) << 8)) << 8)) << 8);

		binKey[0] = (v3 & 0xFF000000) >> 24;
		binKey[1] = (v3 & 0xFF0000) >> 16;
		binKey[2] = (v3 & 0xFF00) >> 8;
		binKey[3] = (v2 ^ 0xF5) & 0xF0;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--车身控制系统—特殊功能
	void CalcSecuAccess_Mode2D(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		BYTE v2 = 0; // r0
		unsigned int v3 = 0; // r0
		unsigned int v4 = 0;
		unsigned int v5 = 0;

		v3 = input;
		v4 = (v3 & 0xFF00) >> 8 ^ 0xEF;
		v2 = input;
		v5 = (unsigned char)((v2 ^ 0x3D) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v3 >> 24) ^ 0x53) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(((((unsigned short)v3 >> 8) ^ 0xEF) >> 4) | 16 * ((v3 & 0xFF0000) >> 16 ^ 0xCC)) | ((((unsigned char)v2 ^ 0x3D) & 0xF0 | (((v3 >> 24) ^ 0x53) >> 4)) << 8)) << 8)) << 8);

		binKey[0] = (v5 >> 24) & 0xFF;
		binKey[1] = (v5 >> 16) & 0xFF;
		binKey[2] = (v5 >> 8) & 0xFF;
		binKey[3] = v5 & 0xFF;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--电子驻锁系统—特殊功能(2组安全算法)-//写入车辆识别代码
	void CalcSecuAccess_Mode2E(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		BYTE v2 = 0; // r0
		unsigned int v3 = 0; // r0
		unsigned int v4 = 0;
		unsigned int v5 = 0;

		v2 = input;
		v3 = input;
		v4 = (v3 & 0xFF00) >> 8 ^ 0x3E;
		v5 = (unsigned char)((v2 ^ 0xA6) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v3 >> 24) ^ 0x5F) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(((((unsigned short)v3 >> 8) ^ 0x3E) >> 4) | 16 * ((v3 & 0xFF0000) >> 16 ^ 0xDE)) | ((((unsigned char)v2 ^ 0xA6) & 0xF0 | (((v3 >> 24) ^ 0x5F) >> 4)) << 8)) << 8)) << 8);

		binKey[0] = (v5 >> 24) & 0xFF;
		binKey[1] = (v5 >> 16) & 0xFF;
		binKey[2] = (v5 >> 8) & 0xFF;
		binKey[3] = v5 & 0xFF;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--电子驻锁系统—特殊功能(2组安全算法)-//写入编程日期
	void CalcSecuAccess_Mode2F(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		BYTE v1 = 0; // r0
		BYTE v5 = 0; // r0
		unsigned int v3 = 0; // r0
		unsigned int v4 = 0;
		unsigned int v2 = 0;

		v2 = input;
		//v3 = ((unsigned short)((*(input + 2) << 8) + *(input + 3)) >> 8) ^ 0x3E;
		v3 = ((unsigned short)(((input + 2) << 8) + (input + 3)) >> 8) ^ 0x3E;
		v1 = (v2 & 0xFF0000) >> 16;
		v4 = ((unsigned char)(8 * (v1 ^ 0xDE)) ^ (unsigned char)(((unsigned char)v2 ^ 0xA6) >> 3)) & 0xF ^ (unsigned char)(8 * (v1 ^ 0xDE)) | (((unsigned char)((v3 >> 2) & 0xF | 16 * ((v2 & 0xFF000000) >> 24 ^ 0x5F)) | (((unsigned char)((v2 ^ v1 ^ 0x78) & 0xF ^ v2 ^ 0xA6) | ((((unsigned char)v3 ^ (unsigned char)(((v2 >> 24) ^ 0x5F) >> 2)) & 0xF ^ v3) << 8)) << 8)) << 8);
		v5 = (v2 & 0xFF0000) >> 16 ^ 0xDE;
		binKey[3] = (8 * v5 ^ (((unsigned char)v2 ^ 0xA6) >> 3)) & 0xF ^ 8 * v5;
		binKey[0] = (v4 & 0xFF000000) >> 24;
		binKey[1] = (v4 & 0xFF0000) >> 16;
		binKey[2] = (v4 & 0xFF00) >> 8;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--MP5—特殊功能
	void CalcSecuAccess_Mode30(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		unsigned int v3 = 0; // r0
		unsigned char v4 = 0;
		unsigned int v2 = 0;

		v2 = input;
		v4 = (v2 & 0xFF00) >> 8 ^ 0x18;
		v3 = (unsigned char)((v2 ^ 0xF4) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v2 >> 24) ^ 0x6E) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(16 * ((v2 & 0xFF0000) >> 16 ^ 0x72) | ((((unsigned short)v2 >> 8) ^ 0x18) >> 4)) | ((unsigned char)((v2 ^ 0xF4) & 0xF0 | (((v2 >> 24) ^ 0x6E) >> 4)) << 8)) << 8)) << 8);
		
		binKey[3] = (v2 ^ 0xF4) & 0xF0;
		binKey[0] = (v3 & 0xFF000000) >> 24;
		binKey[1] = (v3 & 0xFF0000) >> 16;
		binKey[2] = (v3 & 0xFF00) >> 8;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--仪表板系统—动作测试 / 特殊功能
	void CalcSecuAccess_Mode31(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		unsigned int v3 = 0; // r0
		unsigned char v4 = 0;
		unsigned int v2 = 0;
		v2 = input;
		v4 = (v2 & 0xFF00) >> 8 ^ 0x9A;
		v3 = (unsigned char)((v2 ^ 0xFD) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v2 >> 24) ^ 0x37) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(16 * ((v2 & 0xFF0000) >> 16 ^ 0x41) | ((((unsigned short)v2 >> 8) ^ 0x9A) >> 4)) | ((unsigned char)((v2 ^ 0xFD) & 0xF0 | (((v2 >> 24) ^ 0x37) >> 4)) << 8)) << 8)) << 8);
		
		binKey[3] = (v2 ^ 0xFD) & 0xF0;
		binKey[0] = (v3 & 0xFF000000) >> 24;
		binKey[1] = (v3 & 0xFF0000) >> 16;
		binKey[2] = (v3 & 0xFF00) >> 8;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--无钥匙启动系统--动作测试/特殊功能
	void CalcSecuAccess_Mode32(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		unsigned int v3 = 0; // r0
		unsigned char v4 = 0;
		unsigned char v2 = 0;
		unsigned int v5 = 0;

		v3 = input;
		v2 = (unsigned char)v3;
		v4 = (v3 & 0xFF00) >> 8 ^ 0x6B;
		v5 = (unsigned char)((v2 ^ 0xC8) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v3 >> 24) ^ 0x36) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(((((unsigned short)v3 >> 8) ^ 0x6B) >> 4) | 16 * ((v3 & 0xFF0000) >> 16 ^ 0xD5)) | ((((unsigned char)v2 ^ 0xC8) & 0xF0 | (((v3 >> 24) ^ 0x36) >> 4)) << 8)) << 8)) << 8);
		
		binKey[0] = (v5 >> 24) & 0xFF;
		binKey[1] = (v5 >> 16) & 0xFF;
		binKey[2] = (v5 >> 8) & 0xFF;
		binKey[3] = v5 & 0xFF;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--安全气囊系统--特殊功能
	void CalcSecuAccess_Mode33(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		unsigned int v3 = 0; // r0
		unsigned char v4 = 0;
		unsigned char v2 = 0;
		unsigned int v5 = 0;

		v3 = input;
		v2 = (unsigned char)v3;
		v4 = (v3 & 0xFF00) >> 8 ^ 0x2D;

		v5 = (unsigned char)((v2 ^ 0x68) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v3 >> 24) ^ 0xFA) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(((((unsigned short)v3 >> 8) ^ 0x2D) >> 4) | 16 * ((v3 & 0xFF0000) >> 16 ^ 0xA5)) | ((((unsigned char)v2 ^ 0x68) & 0xF0 | (((v3 >> 24) ^ 0xFA) >> 4)) << 8)) << 8)) << 8);

		binKey[0] = (v5 >> 24) & 0xFF;
		binKey[1] = (v5 >> 16) & 0xFF;
		binKey[2] = (v5 >> 8) & 0xFF;
		binKey[3] = v5 & 0xFF;
	}

	//江铃--江西五十铃--瑞迈S--柴油国六--转向角系统--特殊功能
	void CalcSecuAccess_Mode34(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		UINT input = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		if (!binRecvSeed[0] && !binRecvSeed[1])
			return;	//不需要安全算法

		unsigned int v3 = 0; // r0
		unsigned char v4 = 0;
		unsigned int v2 = 0;

		v2 = input;
		v4 = (v2 & 0xFF00) >> 8 ^ 0x38;
		v3 = (unsigned char)((v2 ^ 0x73) & 0xF0) | ((((unsigned char)(8 * v4) ^ (unsigned char)(((v2 >> 24) ^ 0xBC) >> 1)) & 0x1F ^ (unsigned char)(8 * v4) | (((unsigned char)(16 * ((v2 & 0xFF0000) >> 16 ^ 0x45) | ((((unsigned short)v2 >> 8) ^ 0x38) >> 4)) | ((unsigned char)((v2 ^ 0x73) & 0xF0 | (((v2 >> 24) ^ 0xBC) >> 4)) << 8)) << 8)) << 8);
		binKey[3] = (v2 ^ 0x73) & 0xF0;
		binKey[0] = (v3 & 0xFF000000) >> 24;
		binKey[1] = (v3 & 0xFF0000) >> 16;
		binKey[2] = (v3 & 0xFF00) >> 8;
	}
	static BOOL Alg78(BYTE* in, UINT* out)
	{
		UINT akey[] = { 0x01767999, 0x01765808, 0x21565147, 0x11664445 };
		UINT iInput = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | (in[3]);
		//UINT yInput = _byteswap_ulong(*(UINT*)in);
		UINT count = (iInput & 0xF0000) >> 16;
		UINT tmp1 = iInput;
		UINT tmp2 = iInput;
		UINT pos = (iInput & 0x30) >> 4;
		UINT flag = iInput & 8;
		for (int i = 0; i < count && (iInput & 7) != 5; ++i)
		{
			if (flag)
			{
				tmp1 >>= 1;
				tmp2 <<= 0x1F;
			}
			else
			{
				tmp1 <<= 1;
				tmp2 >>= 0x1F;
			}
			tmp1 |= tmp2;
			iInput = tmp1;
			tmp2 = tmp1;
		}

		*out = (iInput ^ akey[pos]);

		return TRUE;
	}

	void CalcSecuAccess_Mode35(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		binKey = CBinary("\x00\x00\x00\x00", 4);
		BYTE* in = NULL;
		UINT out = NULL;
		CBinary binRecv;
		DWORD JMC_GUO6;
		DWORD seed;
		BYTE recevie270A[4] = { 0 };
		for (int k = 0; k < 4; k++)
		{
			recevie270A[k] = binRecvSeed[k];
		}
		in = recevie270A;
		BYTE cmd001 = recevie270A[0];
#if (defined WIN32 && defined NDEBUG)
		VMProtectBegin("CJMC_EDC17C81_GUO6::SafeAccess");
#endif
		Alg78(in, &out);

#if (defined WIN32 && defined NDEBUG)
		VMProtectEnd();
#endif
		binKey[0] = (out >> 24) & 0xFF;
		binKey[1] = (out >> 16) & 0xFF;
		binKey[2] = (out >> 8) & 0xFF;
		binKey[3] = out & 0xFF;

	}

	void CalcSecuAccess_Mode36(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		CBinary binRecvSeed1 = binRecvSeed;
		binRecvSeed1.InsertAt(3, 0x00);
		unsigned int Seed = (binRecvSeed1[0] << 24) +  (binRecvSeed1[1] << 16) + (binRecvSeed1[2] << 8)+binRecvSeed1[3];
		
		binKey = CBinary("\x00\x00\x00\x00", 4);
		unsigned int BitMaskkey[32]; // [sp+8h] [bp-94h] BYREF
		int i; // [sp+88h] [bp-14h]
		unsigned int Key; // [sp+8Ch] [bp-10h]
		unsigned char Temp[] = { 0x4D,0x6E,0x41,0x00,0x9B,0xEF,0x87,0x00,0x36,0xFD,0x0A,0x00,0x7C,0xC8,0x11,0x00,
			0xF8,0xA3,0x27,0x00,0xE1,0x47,0x4F,0x00,0xC2,0x8E,0x9F,0x00,0x94,0x3E,0x3A,0x00,
			0x4E,0x35,0x3F,0x00,0x8C,0x6B,0x7E,0x00,0x19,0xE5,0xF8,0x00,0x23,0xDB,0xF0,0x00,
			0x56,0x94,0xE5,0x00,0xAD,0x38,0xCA,0x00,0x5B,0x53,0x90,0x00,0xA6,0xB7,0x20,0x00,
			0x52,0x7A,0xC9,0x00,0xB5,0xD6,0x97,0x00,0x6B,0xBC,0x2F,0x00,0xD6,0x4B,0x5B,0x00,
			0xBD,0xA4,0xB2,0x00,0x6B,0x59,0x65,0x00,0xD7,0x81,0xCF,0x00,0xAF,0x12,0x9F,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
		int* v6 = (int*)Temp;

		Key = 0x72C880;
		memset(BitMaskkey, 0, sizeof(BitMaskkey));
		BitMaskkey[0] = 0x416E4D;
		BitMaskkey[1] = 0x87EF9B;
		BitMaskkey[2] = 0xAFD36;
		BitMaskkey[3] = 0x11C87C;
		BitMaskkey[4] = 0x27A3F8;
		BitMaskkey[5] = 0x4F47E1;
		BitMaskkey[6] = 0x9F8EC2;
		BitMaskkey[7] = 0x3A3E94;
		BitMaskkey[8] = 0x3F354E;
		BitMaskkey[9] = 0x7E6B8C;
		BitMaskkey[0xA] = 0xF8E519;
		BitMaskkey[0xB] = 0xF0DB23;
		BitMaskkey[0xC] = 0xE59456;
		BitMaskkey[0xD] = 0xCA38AD;
		BitMaskkey[0xE] = 0x90535B;
		BitMaskkey[0xF] = 0x20B7A6;
		BitMaskkey[0x10] = 0xC97A52;
		BitMaskkey[0x11] = 0x97D6B5;
		BitMaskkey[0x12] = 0x2FBC6B;
		BitMaskkey[0x13] = 0x5B4BD6;
		BitMaskkey[0x14] = 0xB2A4BD;
		BitMaskkey[0x15] = 0x65596B;
		BitMaskkey[0x16] = 0xCF81D7;
		BitMaskkey[0x17] = 0x9F12AF;
		for (i = 0; i <= 0x1F; ++i)
		{
			if ((Seed & 1) != 0) {
				int t = v6[i];
				Key ^= t;
			}
			Seed >>= 1;
		}

		Key >>= 8;
		Key &= 0xffffffff;
		//binKey.SetAt(3, 0x00);
		binKey[0] = (Key >> 16) & 0xFF;
		binKey[1] = (Key >> 8) & 0xFF;
		binKey[2] = (Key) & 0xFF;
	}

	void CalcSecuAccess_Mode3A(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#ifdef _VM_PROTECT_
		VMProtectBegin("CWANANQQ_ABS::seedToKey");
#endif // _WINDOWS_

		long num = (long)((unsigned long)binRecvSeed[0]);
		num <<= 24;
		long num2 = (long)((unsigned long)binRecvSeed[1]);
		num2 <<= 16;
		long num3 = (long)((unsigned long)binRecvSeed[2]);
		num3 <<= 8;
		long num4 = (long)((unsigned long)binRecvSeed[3]);
		long num5 = num + num2 + num3 + num4;
		num5 = ((num5 >> 2 ^ num5) << 3 ^ (long)((unsigned long)-869020621));

		binKey.Add(((num5 >> 24) & 255u));
		binKey.Add(((num5 >> 16) & 255u));
		binKey.Add(((num5 >> 8) & 255u));
		binKey.Add(((num5 >> 0) & 255u));

#ifdef _VM_PROTECT_
		VMProtectEnd();
#endif // _WINDOWS_
	}

	void CalcSecuAccess_Mode3B(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
#ifdef _VM_PROTECT_
		VMProtectBegin("CCOMET_ABS::seedToKey");
#endif // _WINDOWS_

		long num = (long)((unsigned long)binRecvSeed[0]);
		num <<= 24;
		long num2 = (long)((unsigned long)binRecvSeed[1]);
		num2 <<= 16;
		long num3 = (long)((unsigned long)binRecvSeed[2]);
		num3 <<= 8;
		long num4 = (long)((unsigned long)binRecvSeed[3]);
		long num5 = num + num2 + num3 + num4;
		num5 = ((num5 >> 2 ^ num5) << 3 ^ 1437226410L);

		binKey.Add(((num5 >> 24) & 255u));
		binKey.Add(((num5 >> 16) & 255u));
		binKey.Add(((num5 >> 8) & 255u));
		binKey.Add(((num5 >> 0) & 255u));

#ifdef _VM_PROTECT_
		VMProtectEnd();
#endif // _WINDOWS_
	}

	/*void CalcSecuAccess_Mode35(const TString & strMask, const CBinary & binRecvSeed, CBinary & binKey)
	{
		WORD i = 0;
		CBinary binKeyValue;
		if (strMask == "04")
		{
			binKeyValue = CBinary("\x4B\xA5\x21\x5C\x3A\x9A\xDE\x8C\x0D\x08\x70\x24\x8C\x79\xAA\xF0", 16);
		}

		BYTE byteKey[8] = { 0 };
		i = 0;
		while (i < binRecvSeed.m_nSize && i < 8)
		{
			byteKey[i] = binRecvSeed[i];
			++i;
		}

		BYTE digist[20] = { 0 };
		BYTE pin[8] = { 0 };
		memset(pin, 0, 8);
		memcpy(pin, byteKey, 8);

		SHA1B3_CTX sha1c;
		SHA1B3_Init(&sha1c);
		SHA1B3_Update(&sha1c, binKeyValue.GetBuffer(), 16);
		if (strMask == "04")
		{
			SHA1B3_Update(&sha1c, pin, 4);
		}
		else
		{
			SHA1B3_Update(&sha1c, pin, 8);
		}
		SHA1B3_Final(digist, &sha1c);

		if (strMask == "04")
		{
			for (i = 0; i < 4; ++i)
			{
				binKey += (unsigned char)digist[i];
			}
		}
		else
		{
			for (i = 0; i < 8; ++i)
			{
				binKey += (unsigned char)digist[i];
			}
		}
	}*/
	UINT uCalResult[32] = { 0 };
	BYTE uArr3650[] = { 56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1,58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 62, 54, 46, 38,30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36,28, 20, 12, 4, 27, 19, 11, 3 };
	BYTE uArr3610[] = { 128, 0, 64, 0, 32, 0, 16, 0, 8, 0, 4, 0, 2, 0, 1, 0 };
	BYTE uArr3888[] = { 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28 };
	BYTE uArr3620[] = { 13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1 };
	BYTE uArr3638[] = { 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55,33, 52, 45, 41, 49, 35, 28, 31 };
	UINT uArr33B0[] = { 8388608, 4194304, 2097152, 1048576, 524288, 262144, 131072, 65536, 32768, 16384, 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1 };
	UINT uArr3410[64] = { 2097152, 69206018, 67110914, 0, 2048, 67110914, 2099202, 69208064,69208066, 2097152, 0, 67108866, 2, 67108864, 69206018, 2050,67110912, 2099202, 2097154, 67110912, 67108866, 69206016, 69208064, 2097154,69206016, 2048, 2050, 69208066, 2099200, 2, 67108864, 2099200,67108864, 2099200, 2097152, 67110914,67110914 , 69206018, 69206018, 2, 2097154, 67108864,67110912, 2097152, 69208064, 2050, 2099202, 69208064, 2050, 67108866,69208066, 69206016, 2099200, 0, 2, 69208066, 0, 2099202,69206016, 2048, 67108866, 67110912, 2048, 2097154 };
	UINT uArr3510[64] = { 520, 134349312, 0, 134348808, 134218240, 0, 131592, 134218240,131080, 134217736, 134217736, 131072, 134349320, 131080, 134348800, 520, 134217728,8, 134349312, 512, 131584, 134348800, 134348808, 131592, 134218248,131584, 131072, 134218248, 8, 134349320, 512, 134217728, 134349312,134217728, 131080, 520, 131072, 134349312, 134218240, 0, 512,131080, 134349320, 134218240, 134217736, 512, 0, 134348808, 134218248,131072, 134217728, 134349320, 8, 131592, 131584, 134217736, 134348800,134218248, 520, 134348800, 131592, 8, 134348808, 131584 };
	UINT uArr3898[64] = { 256, 34078976, 34078720, 1107296512, 524288, 256, 1073741824, 34078720,1074266368, 524288, 33554688, 1074266368, 1107296512, 1107820544, 524544, 1073741824, 33554432, 1074266112,1074266112, 0, 1073742080, 1107820800,1107820800, 33554688, 1107820544, 1073742080,0, 1107296256, 34078976, 33554432, 1107296256, 524544, 524288, 1107296512,256, 33554432, 1073741824, 34078720, 1107296512, 1074266368, 33554688, 1073741824,1107820544, 34078976, 1074266368, 256, 33554432, 1107820544, 1107820800, 524544,1107296256, 1107820800, 34078720, 0, 1074266112, 1107296256, 524544, 33554688,1073742080, 524288, 0, 1074266112, 34078976, 1073742080 };
	UINT uArr30B0[64] = { 16843776, 0, 65536, 16843780, 16842756, 66564, 4, 65536, 1024, 16843776, 16843780, 1024, 16778244, 16842756, 16777216, 4,1028, 16778240,16778240, 66560,66560, 16842752,16842752, 16778244, 65540, 16777220,16777220, 65540,0, 1028, 66564, 16777216, 65536, 16843780, 4, 16842752,16843776, 16777216, 16777216, 1024, 16842756, 65536, 66560, 16777220, 1024,4, 16778244, 66564, 16843780, 65540, 16842752, 16778244, 16777220,1028, 66564, 16843776, 1028, 16778240, 16778240, 0, 65540, 66560,0, 16842756 };
	UINT uArr32B0[64] = { 268439616, 4096, 262144, 268701760, 268435456, 268439616, 64, 268435456,262208, 268697600, 268701760, 266240, 268701696, 266304, 4096, 64,268697600, 268435520, 268439552, 4160, 266240, 262208, 268697664, 268701696,4160, 0,0 , 268697664, 268435520, 268439552, 266304, 262144, 266304,262144, 268701696, 4096, 64, 268697664, 4096, 266304, 268439552,64, 268435520, 268697600, 268697664, 268435456, 262144, 268439616, 0,268701760, 262208, 268435520, 268697600, 268439552, 268439616, 0, 268701760,266240, 266240, 4160, 4160, 262208, 268435456, 268701696 };
	UINT uArr3788[64] = { 536870928, 541065216, 16384, 541081616, 541065216, 16, 541081616, 4194304,536887296, 4210704, 4194304, 536870928, 4194320, 536887296, 536870912, 16400,0, 4194320, 536887312, 16384, 4210688, 536887312, 16, 541065232, 541065232,0, 4210704, 541081600, 16400, 4210688, 541081600, 536870912, 536887296,16, 541065232, 4210688, 541081616, 4194304, 16400, 536870928, 4194304,536887296, 536870912, 16400, 536870928, 541081616, 4210688, 541065216, 4210704,541081600, 0, 541065232, 16, 16384, 541065216, 4210704, 16384,4194320, 536887312, 0, 541081600, 536870912, 4194320, 536887312 };
	UINT uArr31B0[64] = { 8396801, 8321,8321, 128, 8396928, 8388737, 8388609, 8193, 0,8396800,8396800, 8396929, 129, 0, 8388736, 8388609, 1, 8192,8388608, 8396801, 128, 8388608, 8193, 8320, 8388737, 1,8320, 8388736, 8192, 8396928, 8396929, 129, 8388736, 8388609,8396800, 8396929, 129, 0, 0, 8396800, 8320, 8388736, 8388737,1, 8396801, 8321,8321, 128, 8396929, 129, 1, 8192,8388609, 8193, 8396928, 8388737, 8193, 8320, 8388608, 8396801,128, 8388608, 8192, 8396928 };
	UINT uArr3688[64] = { 2148565024, 2147516416, 32768, 1081376, 1048576, 32, 2148532256, 2147516448, 2147483680, 2148565024, 2148564992, 2147483648, 2147516416, 1048576, 32, 2148532256,1081344, 1048608, 2147516448, 0, 2147483648, 32768, 1081376, 2148532224,1048608, 2147483680, 0, 1081344, 32800, 2148564992, 2148532224, 32800,0, 1081376, 2148532256, 1048576, 2147516448, 2148532224, 2148564992, 32768,2148532224, 2147516416, 32, 2148565024, 1081376, 32, 32768, 2147483648,32800, 2148564992, 1048576, 2147483680, 1048608, 2147516448, 2147483680, 1048608,1081344, 0, 2147516416, 32800, 2147483648, 2148532256, 2148565024, 1081344 };

	int sub_10001191(UINT* a1)
	{
		UINT* v1; // ebx
		UINT v2; // esi
		UINT v3; // edi
		UINT result; // eax
		BOOL v5; // zf
		int v6; // [esp+Ch] [ebp-8Ch]
		UINT* v7; // [esp+10h] [ebp-88h]
		UINT v8[32]; // [esp+14h] [ebp-84h]

		v6 = 16;
		v1 = a1;
		v7 = v8;
		do
		{
			v2 = *v1;
			v1 += 2;
			v3 = *(v1 - 1);
			*v7 = ((*(v1 - 1) & 0xFC0 | (*(v1 - 1) >> 4) & 0xFC000) >> 6) | ((v2 & 0xFC0000 | 16 * (v2 & 0xFC0)) << 6);
			result = (v3 >> 4) & 0x3F00;
			v7[1] = v3 & 0x3F | result | ((v2 & 0x3F000 | 16 * (v2 & 0x3F)) << 12);
			v5 = v6-- == 1;
			v7 += 2;
		} while (!v5);
		memcpy(uCalResult, v8, sizeof(uCalResult));

		return result;
	}

	int sub_10001000(BYTE* a1)
	{
		BYTE* v1; // edi
		int v2; // esi
		int v3; // ecx
		BOOL v4; // zf
		int v5; // ecx
		int v6; // ecx
		int v7; // ebx
		int v8; // eax
		int v9; // edx
		int v10; // ecx
		char v11; // al
		int v12; // edx
		int v13; // ecx
		char v14; // al
		int v15; // eax
		int v17; // [esp+Ch] [ebp-F8h]
		UINT v18[32] = { 0 }; // [esp+10h] [ebp-F4h]
		char v19[56] = { 0 };; // [esp+90h] [ebp-74h]
		char v20[56] = { 0 }; // [esp+C8h] [ebp-3Ch]

		v1 = a1;
		v2 = 0;
		do
		{
			v3 = uArr3650[v2 + 1];
			v20[v2] = (v1[(int)uArr3650[v2] >> 3] & uArr3610[2 * (uArr3650[v2] & 7)]) != 0;
			v4 = (v1[v3 >> 3] & uArr3610[2 * (v3 & 7)]) == 0;
			v5 = uArr3650[v2 + 2];
			v20[v2 + 1] = !v4;
			v4 = (v1[v5 >> 3] & uArr3610[2 * (v5 & 7)]) == 0;
			v6 = uArr3650[v2 + 3];
			v20[v2 + 2] = !v4;
			v20[v2 + 3] = (v1[v6 >> 3] & uArr3610[2 * (v6 & 7)]) != 0;
			v2 += 4;
		} while (v2 < 56);
		v7 = 0;
		do
		{
			v8 = 2 * v7;
			v9 = 0;
			v18[v8 + 1] = 0;
			v18[v8] = 0;
			v17 = uArr3888[v7];
			v10 = uArr3888[v7];
			do
			{
				if (v10 >= 28)
					v11 = v20[v10 - 28];
				else
					v11 = v20[v10];
				v19[v9] = v11;
				++v10;
				++v9;
			} while (v9 < 28);
			v12 = 28;
			v13 = v17 + 28;
			do
			{
				if (v13 >= 56)
					v14 = v20[v13 - 28];
				else
					v14 = v20[v13];
				v19[v12] = v14;
				++v13;
				++v12;
			} while (v12 < 56);
			v15 = 0;
			do
			{
				if (v19[uArr3620[v15]])
					v18[2 * v7] |= uArr33B0[v15];
				if (v19[uArr3638[v15]])
					v18[2 * v7 + 1] |= uArr33B0[v15];
				++v15;
			} while (v15 < 24);
			++v7;
		} while (v7 < 16);
		return sub_10001191(v18);
	}

	int sub_100012F0(UINT* a1)
	{
		UINT v1; // edx
		UINT v2; // eax
		int v3; // edx
		UINT v4; // esi
		int v5; // eax
		UINT v6; // edx
		int v7; // esi
		int v8; // eax
		int v9; // esi
		UINT v10; // edx
		int v11; // ebx
		int v12; // esi
		int v13; // ebx
		UINT v14; // edi
		int v15; // ebx
		int v16; // edi
		int v17; // ebx
		int v18; // edi
		int v19; // ebx
		int v20; // edi
		int v21; // ebx
		int v22; // edi
		int v23; // ebx
		int v24; // edi
		int v25; // ebx
		int v26; // edi
		int v27; // ebx
		int v28; // edi
		int v29; // ebx
		int v30; // edi
		int v31; // ebx
		UINT v32; // edx
		int v33; // ebx
		UINT v34; // edx
		int v35; // eax
		int v36; // ebx
		UINT v37; // edx
		int v38; // eax
		int v39; // ebx
		int v40; // edx
		int v41; // eax
		int v42; // edx
		UINT v43; // ebx
		int result; // eax

		v1 = a1[1];
		v2 = (v1 ^ (*a1 >> 4)) & 0xF0F0F0F;
		v3 = v2 ^ v1;
		v4 = 16 * v2 ^ *a1;
		v5 = (WORD)(v3 ^ ((v4 >> 16) & 0xFFFF));
		v6 = v5 ^ v3;
		v7 = (v5 << 16) ^ v4;
		v8 = (v7 ^ (v6 >> 2)) & 0x33333333;
		v9 = v8 ^ v7;
		v10 = 4 * v8 ^ v6;
		v11 = (v9 ^ (v10 >> 8)) & 0xFF00FF;
		v12 = v11 ^ v9;
		v13 = __ROL4__(v10 ^ (v11 << 8), 1);
		v14 = (v12 ^ v13) & 0xAAAAAAAA;
		v15 = v14 ^ v13;
		v16 = (uArr3410[(uCalResult[0] ^ __ROR4__(v15, 4)) & 0x3F] | uArr3898[((uCalResult[0] ^ __ROR4__(v15, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[0] ^ __ROR4__(v15, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[0] ^ __ROR4__(v15, 4)) >> 24) & 0x3F] | uArr32B0[(v15 ^ uCalResult[1]) & 0x3F] | uArr3788[((v15 ^ uCalResult[1]) >> 8) & 0x3F] | uArr31B0[((v15 ^ uCalResult[1]) >> 16) & 0x3F] | uArr3688[((v15 ^ uCalResult[1]) >> 24) & 0x3F]) ^ __ROL4__(v12 ^ v14, 1);
		v17 = (uArr3410[(uCalResult[2] ^ __ROR4__(v16, 4)) & 0x3F] | uArr3898[((uCalResult[2] ^ __ROR4__(v16, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[2] ^ __ROR4__(v16, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[2] ^ __ROR4__(v16, 4)) >> 24) & 0x3F] | uArr32B0[(v16 ^ uCalResult[3]) & 0x3F] | uArr3788[((v16 ^ uCalResult[3]) >> 8) & 0x3F] | uArr31B0[((v16 ^ uCalResult[3]) >> 16) & 0x3F] | uArr3688[((v16 ^ uCalResult[3]) >> 24) & 0x3F]) ^ v15;
		v18 = (uArr3410[(uCalResult[4] ^ __ROR4__(v17, 4)) & 0x3F] | uArr3898[((uCalResult[4] ^ __ROR4__(v17, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[4] ^ __ROR4__(v17, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[4] ^ __ROR4__(v17, 4)) >> 24) & 0x3F] | uArr32B0[(v17 ^ uCalResult[5]) & 0x3F] | uArr3788[((v17 ^ uCalResult[5]) >> 8) & 0x3F] | uArr31B0[((v17 ^ uCalResult[5]) >> 16) & 0x3F] | uArr3688[((v17 ^ uCalResult[5]) >> 24) & 0x3F]) ^ v16;
		v19 = (uArr3410[(uCalResult[6] ^ __ROR4__(v18, 4)) & 0x3F] | uArr3898[((uCalResult[6] ^ __ROR4__(v18, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[6] ^ __ROR4__(v18, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[6] ^ __ROR4__(v18, 4)) >> 24) & 0x3F] | uArr32B0[(v18 ^ uCalResult[7]) & 0x3F] | uArr3788[((v18 ^ uCalResult[7]) >> 8) & 0x3F] | uArr31B0[((v18 ^ uCalResult[7]) >> 16) & 0x3F] | uArr3688[((v18 ^ uCalResult[7]) >> 24) & 0x3F]) ^ v17;
		v20 = (uArr3410[(uCalResult[8] ^ __ROR4__(v19, 4)) & 0x3F] | uArr3898[((uCalResult[8] ^ __ROR4__(v19, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[8] ^ __ROR4__(v19, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[8] ^ __ROR4__(v19, 4)) >> 24) & 0x3F] | uArr32B0[(v19 ^ uCalResult[9]) & 0x3F] | uArr3788[((v19 ^ uCalResult[9]) >> 8) & 0x3F] | uArr31B0[((v19 ^ uCalResult[9]) >> 16) & 0x3F] | uArr3688[((v19 ^ uCalResult[9]) >> 24) & 0x3F]) ^ v18;
		v21 = (uArr3410[(uCalResult[10] ^ __ROR4__(v20, 4)) & 0x3F] | uArr3898[((uCalResult[10] ^ __ROR4__(v20, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[10] ^ __ROR4__(v20, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[10] ^ __ROR4__(v20, 4)) >> 24) & 0x3F] | uArr32B0[(v20 ^ uCalResult[11]) & 0x3F] | uArr3788[((v20 ^ uCalResult[11]) >> 8) & 0x3F] | uArr31B0[((v20 ^ uCalResult[11]) >> 16) & 0x3F] | uArr3688[((v20 ^ uCalResult[11]) >> 24) & 0x3F]) ^ v19;
		v22 = (uArr3410[(uCalResult[12] ^ __ROR4__(v21, 4)) & 0x3F] | uArr3898[((uCalResult[12] ^ __ROR4__(v21, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[12] ^ __ROR4__(v21, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[12] ^ __ROR4__(v21, 4)) >> 24) & 0x3F] | uArr32B0[(v21 ^ uCalResult[13]) & 0x3F] | uArr3788[((v21 ^ uCalResult[13]) >> 8) & 0x3F] | uArr31B0[((v21 ^ uCalResult[13]) >> 16) & 0x3F] | uArr3688[((v21 ^ uCalResult[13]) >> 24) & 0x3F]) ^ v20;
		v23 = (uArr3410[(uCalResult[14] ^ __ROR4__(v22, 4)) & 0x3F] | uArr3898[((uCalResult[14] ^ __ROR4__(v22, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[14] ^ __ROR4__(v22, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[14] ^ __ROR4__(v22, 4)) >> 24) & 0x3F] | uArr32B0[(v22 ^ uCalResult[15]) & 0x3F] | uArr3788[((v22 ^ uCalResult[15]) >> 8) & 0x3F] | uArr31B0[((v22 ^ uCalResult[15]) >> 16) & 0x3F] | uArr3688[((v22 ^ uCalResult[15]) >> 24) & 0x3F]) ^ v21;
		v24 = (uArr3410[(uCalResult[16] ^ __ROR4__(v23, 4)) & 0x3F] | uArr3898[((uCalResult[16] ^ __ROR4__(v23, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[16] ^ __ROR4__(v23, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[16] ^ __ROR4__(v23, 4)) >> 24) & 0x3F] | uArr32B0[(v23 ^ uCalResult[17]) & 0x3F] | uArr3788[((v23 ^ uCalResult[17]) >> 8) & 0x3F] | uArr31B0[((v23 ^ uCalResult[17]) >> 16) & 0x3F] | uArr3688[((v23 ^ uCalResult[17]) >> 24) & 0x3F]) ^ v22;
		v25 = (uArr3410[(uCalResult[18] ^ __ROR4__(v24, 4)) & 0x3F] | uArr3898[((uCalResult[18] ^ __ROR4__(v24, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[18] ^ __ROR4__(v24, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[18] ^ __ROR4__(v24, 4)) >> 24) & 0x3F] | uArr32B0[(v24 ^ uCalResult[19]) & 0x3F] | uArr3788[((v24 ^ uCalResult[19]) >> 8) & 0x3F] | uArr31B0[((v24 ^ uCalResult[19]) >> 16) & 0x3F] | uArr3688[((v24 ^ uCalResult[19]) >> 24) & 0x3F]) ^ v23;
		v26 = (uArr3410[(uCalResult[20] ^ __ROR4__(v25, 4)) & 0x3F] | uArr3898[((uCalResult[20] ^ __ROR4__(v25, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[20] ^ __ROR4__(v25, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[20] ^ __ROR4__(v25, 4)) >> 24) & 0x3F] | uArr32B0[(v25 ^ uCalResult[21]) & 0x3F] | uArr3788[((v25 ^ uCalResult[21]) >> 8) & 0x3F] | uArr31B0[((v25 ^ uCalResult[21]) >> 16) & 0x3F] | uArr3688[((v25 ^ uCalResult[21]) >> 24) & 0x3F]) ^ v24;
		v27 = (uArr3410[(uCalResult[22] ^ __ROR4__(v26, 4)) & 0x3F] | uArr3898[((uCalResult[22] ^ __ROR4__(v26, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[22] ^ __ROR4__(v26, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[22] ^ __ROR4__(v26, 4)) >> 24) & 0x3F] | uArr32B0[(v26 ^ uCalResult[23]) & 0x3F] | uArr3788[((v26 ^ uCalResult[23]) >> 8) & 0x3F] | uArr31B0[((v26 ^ uCalResult[23]) >> 16) & 0x3F] | uArr3688[((v26 ^ uCalResult[23]) >> 24) & 0x3F]) ^ v25;
		v28 = (uArr3410[(uCalResult[24] ^ __ROR4__(v27, 4)) & 0x3F] | uArr3898[((uCalResult[24] ^ __ROR4__(v27, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[24] ^ __ROR4__(v27, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[24] ^ __ROR4__(v27, 4)) >> 24) & 0x3F] | uArr32B0[(v27 ^ uCalResult[25]) & 0x3F] | uArr3788[((v27 ^ uCalResult[25]) >> 8) & 0x3F] | uArr31B0[((v27 ^ uCalResult[25]) >> 16) & 0x3F] | uArr3688[((v27 ^ uCalResult[25]) >> 24) & 0x3F]) ^ v26;
		v29 = (uArr3410[(uCalResult[26] ^ __ROR4__(v28, 4)) & 0x3F] | uArr3898[((uCalResult[26] ^ __ROR4__(v28, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[26] ^ __ROR4__(v28, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[26] ^ __ROR4__(v28, 4)) >> 24) & 0x3F] | uArr32B0[(v28 ^ uCalResult[27]) & 0x3F] | uArr3788[((v28 ^ uCalResult[27]) >> 8) & 0x3F] | uArr31B0[((v28 ^ uCalResult[27]) >> 16) & 0x3F] | uArr3688[((v28 ^ uCalResult[27]) >> 24) & 0x3F]) ^ v27;
		v30 = (uArr3410[(uCalResult[28] ^ __ROR4__(v29, 4)) & 0x3F] | uArr3898[((uCalResult[28] ^ __ROR4__(v29, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[28] ^ __ROR4__(v29, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[28] ^ __ROR4__(v29, 4)) >> 24) & 0x3F] | uArr32B0[(v29 ^ uCalResult[29]) & 0x3F] | uArr3788[((v29 ^ uCalResult[29]) >> 8) & 0x3F] | uArr31B0[((v29 ^ uCalResult[29]) >> 16) & 0x3F] | uArr3688[((v29 ^ uCalResult[29]) >> 24) & 0x3F]) ^ v28;
		v31 = __ROR4__(
			(uArr3410[(uCalResult[30] ^ __ROR4__(v30, 4)) & 0x3F] | uArr3898[((uCalResult[30] ^ __ROR4__(v30, 4)) >> 8) & 0x3F] | uArr3510[((uCalResult[30] ^ __ROR4__(v30, 4)) >> 16) & 0x3F] | uArr30B0[((uCalResult[30] ^ __ROR4__(v30, 4)) >> 24) & 0x3F] | uArr32B0[(v30 ^ uCalResult[31]) & 0x3F] | uArr3788[((v30 ^ uCalResult[31]) >> 8) & 0x3F] | uArr31B0[((v30 ^ uCalResult[31]) >> 16) & 0x3F] | uArr3688[((v30 ^ uCalResult[31]) >> 24) & 0x3F]) ^ v29,
			1);
		v32 = (v30 ^ v31) & 0xAAAAAAAA;
		v33 = v32 ^ v31;
		v34 = __ROR4__(v30 ^ v32, 1);
		v35 = (v33 ^ (v34 >> 8)) & 0xFF00FF;
		v36 = v35 ^ v33;
		v37 = (v35 << 8) ^ v34;
		v38 = (v36 ^ (v37 >> 2)) & 0x33333333;
		v39 = v38 ^ v36;
		v40 = 4 * v38 ^ v37;
		v41 = (WORD)(v40 ^ ((v39 >> 16) & 0xFFFF));
		v42 = v41 ^ v40;
		v43 = (v41 << 16) ^ v39;
		result = v43 ^ 16 * ((v42 ^ (v43 >> 4)) & 0xF0F0F0F);
		*a1 = result;
		a1[1] = v42 ^ (v42 ^ (v43 >> 4)) & 0xF0F0F0F;

		return result;
	}

	UINT sub_10001260(BYTE* a1, BYTE* a2)
	{
		BYTE* v2; // ebx
		BYTE* v3; // edi
		UINT v4; // esi
		int v5; // ecx
		UINT result; // eax
		UINT v8[2]; // [esp+Ch] [ebp-8h]

		v2 = a2;
		v3 = a1 + 1;
		//v4 = _byteswap_ulong(*(UINT *)a1);
		v4 = a1[3] | ((a1[2] | ((a1[1] | (*a1 << 8)) << 8)) << 8);
		v5 = (a1[5] << 16) | (a1[4] << 24);
		v8[0] = v4;
		v8[1] = v3[6] | (v3[5] << 8) | v5;
		sub_100012F0(v8);
		*v2 = (v8[0] >> 24) & 0xFF;
		v2[1] = (v8[0] >> 16) & 0xFF;
		v2[2] = (v8[0] >> 8) & 0xFF;
		v2[3] = v8[0] & 0xFF;
		v2[4] = (v8[1] >> 24) & 0xFF;
		v2[5] = (v8[1] >> 16) & 0xFF;
		v2[6] = (v8[1] >> 8) & 0xFF;
		v2[7] = v8[1] & 0xFF;
		result = v8[1];

		return result;
	}
	//后处理 - DDi13 - 迪耐斯国六
	//void CalcSecuAccess_Mode3B(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	//void CalcSecuAccess_Mode57(BYTE* ucReqBuff, BYTE* ucAnsBuff, int mode)
	void CalcSecuAccess_Mode57(const TString& strMask, const CBinary& binRecvSeed, CBinary& binKey)
	{
		//BYTE* ucReqBuff;
		//BYTE* ucAnsBuff;
		int v2; // ebx
		int result; // eax
		BYTE a2[8]; // [esp+14h] [ebp-14h]
		BYTE v5[8]; // [esp+1Ch] [ebp-Ch]
		*(UINT*)a2 = 0x90BF12AC;
		*(UINT*)&a2[4] = 0xDFE2F19;
		//v2 = ucReqBuff[3] | ((ucReqBuff[2] | ((ucReqBuff[1] | (*ucReqBuff << 8)) << 8)) << 8);
		v2 = (binRecvSeed[0] << 24) + (binRecvSeed[1] << 16) + (binRecvSeed[2] << 8) + binRecvSeed[3];
		v5[3] = v2 & 0xFF;
		v5[7] = v2 & 0xFF;
		v5[0] = (v2 >> 24) & 0xFF;
		v5[4] = (v2 >> 24) & 0xFF;
		v5[1] = (v2 >> 16) & 0xFF;
		v5[5] = (v2 >> 16) & 0xFF;
		v5[2] = (v2 >> 8) & 0xFF;
		v5[6] = (v2 >> 8) & 0xFF;
		sub_10001000(a2);
		sub_10001260(v5, a2);
		for (int i = 0; i < 4; i++)
			binKey.Add(a2[i+4]);

		//result = a2[4];

		//return result;
	}

	void DGX_BCM_method(UINT* uD_I32_0, UINT* uD_I32_1)
	{
		UINT num = uD_I32_0[0];
		UINT num2 = uD_I32_0[1];
		UINT num3 = uD_I32_0[2];
		UINT num4 = uD_I32_0[3];
		UINT num5 = 0U;
		UINT num6 = 2654435769U;
		UINT num7 = uD_I32_1[0];
		UINT num8 = uD_I32_1[1];
		UINT num9 = uD_I32_1[2];
		UINT num10 = uD_I32_1[3];
		for (UINT num11 = 0; num11 < 32; num11 += 1U)
		{
			num5 += num6;
			num += ((num2 << 4) + num7 ^ num2 + num5 ^ (num2 >> 5) + num8);
			num2 += ((num << 4) + num9 ^ num + num5 ^ (num >> 5) + num10);
			num3 += ((num4 << 4) + num7 ^ num4 + num5 ^ (num4 >> 5) + num8);
			num4 += ((num3 << 4) + num9 ^ num3 + num5 ^ (num3 >> 5) + num10);
		}
		uD_I32_0[0] = num;
		uD_I32_0[1] = num2;
		uD_I32_0[2] = num3;
		uD_I32_0[3] = num4;
	}
	//method_1
	BOOL DGX_BCM_Security_59(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey)
	{
		UINT array[4] = { 0 };

		if (uReqLen != 4)
		{
			return false;
		}
		for (int i = 0; i < uReqLen; i++)
		{
			array[i] = ucReqBuff[i];
		}
		UINT num = array[3];
		num |= array[2] << 8;
		num |= array[1] << 16;
		num |= array[0] << 24;

		UINT array2[4] = { 0 };
		UINT array3[4] =
		{
			num,
			15794176U,
			16843010U,
			50595078U
		};
		if (uMode == 7)
		{
			array2[0] = 838953072U;
			array2[1] = 1736868967U;
			array2[2] = 679328463U;
			array2[3] = 800435201U;
		}
		else
		{
			if (uMode != 5)
			{
				return false;
			}
			array2[0] = 839018608U;
			array2[1] = 1736868967U;
			array2[2] = 2684017868U;
			array2[3] = 408599554U;
		}
		DGX_BCM_method(array3, array2);
		//ucAnsBuff[15] = array3[3] & 0xFF;
		//ucAnsBuff[14] = (array3[3] >> 8) & 0xFF;
		//ucAnsBuff[13] = (array3[3] >> 16) & 0xFF;
		//ucAnsBuff[12] = (array3[3] >> 24) & 0xFF;
		//ucAnsBuff[11] = array3[2] & 0xFF;
		//ucAnsBuff[10] = (array3[2] >> 8) & 0xFF;
		//ucAnsBuff[9] = (array3[2] >> 16) & 0xFF;
		//ucAnsBuff[8] = (array3[2] >> 24) & 0xFF;
		//ucAnsBuff[7] = array3[1] & 0xFF;
		//ucAnsBuff[6] = (array3[1] >> 8) & 0xFF;
		//ucAnsBuff[5] = (array3[1] >> 16) & 0xFF;
		//ucAnsBuff[4] = (array3[1] >> 24) & 0xFF;
		//ucAnsBuff[3] = array3[0] & 0xFF;
		//ucAnsBuff[2] = (array3[0] >> 8) & 0xFF;
		//ucAnsBuff[1] = (array3[0] >> 16) & 0xFF;
		//ucAnsBuff[0] = (array3[0] >> 24) & 0xFF;
		for (int n = 0; n < 4; ++n)
		{
			binKey.Add((array3[n] >> 24) & 0xFF);
			binKey.Add((array3[n] >> 16) & 0xFF);
			binKey.Add((array3[n] >> 8) & 0xFF);
			binKey.Add(array3[n] & 0xFF);
		}
		return true;
	}

	void DGX_LDCM_method(UINT* uD_I32_0, UINT* uD_I32_1)
	{
		UINT num = uD_I32_0[0];
		UINT num2 = uD_I32_0[1];
		UINT num3 = uD_I32_0[2];
		UINT num4 = uD_I32_0[3];
		UINT num5 = 0U;
		UINT num6 = 2654435769U;
		UINT num7 = uD_I32_1[0];
		UINT num8 = uD_I32_1[1];
		UINT num9 = uD_I32_1[2];
		UINT num10 = uD_I32_1[3];
		for (UINT num11 = 0U; num11 < 32U; num11 += 1U)
		{
			num5 += num6;
			num += ((num2 << 4) + num7 ^ num2 + num5 ^ (num2 >> 5) + num8);
			num2 += ((num << 4) + num9 ^ num + num5 ^ (num >> 5) + num10);
			num3 += ((num4 << 4) + num7 ^ num4 + num5 ^ (num4 >> 5) + num8);
			num4 += ((num3 << 4) + num9 ^ num3 + num5 ^ (num3 >> 5) + num10);
		}
		uD_I32_0[0] = num;
		uD_I32_0[1] = num2;
		uD_I32_0[2] = num3;
		uD_I32_0[3] = num4;
	}

	// Token: 0x06002967 RID: 10599 RVA: 0x002664B4 File Offset: 0x002646B4
	BOOL DGX_LDCM_Security_5A(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey)
	{
		UINT array[4] = { 0 };
		if (uReqLen != 4)
		{
			return false;
		}
		for (int i = 0; i < uReqLen; i++)
		{
			array[i] = ucReqBuff[i];
		}
		UINT num = array[3];
		num |= array[2] << 8;
		num |= array[1] << 16;
		num |= array[0] << 24;
		UINT array2[4] = { 0 };
		UINT array3[4] =
		{
			num,
			15794176U,
			16843010U,
			50595078U
		};
		if (uMode == 7)
		{
			array2[0] = 3959515248U;
			array2[1] = 1736868967U;
			array2[2] = 2949876675U;
			array2[3] = 1621848065U;
		}
		else
		{
			if (uMode != 5)
			{
				return false;
			}
			array2[0] = 3959580784U;
			array2[1] = 1736868967U;
			array2[2] = 414571202U;
			array2[3] = 2572860674U;
		}
		DGX_LDCM_method(array3, array2);
		for (int n = 0; n < 4; ++n)
		{
			binKey.Add((array3[n] >> 24) & 0xFF);
			binKey.Add((array3[n] >> 16) & 0xFF);
			binKey.Add((array3[n] >> 8) & 0xFF);
			binKey.Add(array3[n] & 0xFF);
		}
		return true;
	}

	void DGX_RDCM_method(UINT* uD_I32_0, UINT* uD_I32_1)
	{
		UINT num = uD_I32_0[0];
		UINT num2 = uD_I32_0[1];
		UINT num3 = uD_I32_0[2];
		UINT num4 = uD_I32_0[3];
		UINT num5 = 0U;
		UINT num6 = 2654435769U;
		UINT num7 = uD_I32_1[0];
		UINT num8 = uD_I32_1[1];
		UINT num9 = uD_I32_1[2];
		UINT num10 = uD_I32_1[3];
		for (UINT num11 = 0U; num11 < 32U; num11 += 1U)
		{
			num5 += num6;
			num += ((num2 << 4) + num7 ^ num2 + num5 ^ (num2 >> 5) + num8);
			num2 += ((num << 4) + num9 ^ num + num5 ^ (num >> 5) + num10);
			num3 += ((num4 << 4) + num7 ^ num4 + num5 ^ (num4 >> 5) + num8);
			num4 += ((num3 << 4) + num9 ^ num3 + num5 ^ (num3 >> 5) + num10);
		}
		uD_I32_0[0] = num;
		uD_I32_0[1] = num2;
		uD_I32_0[2] = num3;
		uD_I32_0[3] = num4;
	}

	// Token: 0x06002972 RID: 10610 RVA: 0x00266BE4 File Offset: 0x00264DE4
	BOOL DGX_RDCM_Security_5B(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey)
	{
		UINT array[4] = { 0 };
		if (uReqLen != 4)
		{
			return false;
		}
		for (int i = 0; i < uReqLen; i++)
		{
			array[i] = ucReqBuff[i];
		}
		UINT num = array[3];
		num |= array[2] << 8;
		num |= array[1] << 16;
		num |= array[0] << 24;
		UINT array2[4] = { 0 };
		UINT array3[4] =
		{
			num,
			15794176U,
			16843010U,
			50595078U
		};
		if (uMode == 7)
		{
			array2[0] = 3976292464U;
			array2[1] = 1736868967U;
			array2[2] = 2071682472U;
			array2[3] = 1840946433U;
		}
		else
		{
			if (uMode != 5)
			{
				return false;
			}
			array2[0] = 3976358000U;
			array2[1] = 1736868967U;
			array2[2] = 561691821U;
			array2[3] = 3145391106U;
		}
		DGX_RDCM_method(array3, array2);
		for (int n = 0; n < 4; ++n)
		{
			binKey.Add((array3[n] >> 24) & 0xFF);
			binKey.Add((array3[n] >> 16) & 0xFF);
			binKey.Add((array3[n] >> 8) & 0xFF);
			binKey.Add(array3[n] & 0xFF);
		}
		return true;
	}

	// Token: 0x06002951 RID: 10577 RVA: 0x00260FC8 File Offset: 0x0025F1C8
	void DGX_CIOM_method(UINT* uD_I32_0, UINT* uD_I32_1)
	{
		UINT num = uD_I32_0[0];
		UINT num2 = uD_I32_0[1];
		UINT num3 = uD_I32_0[2];
		UINT num4 = uD_I32_0[3];
		UINT num5 = 0U;
		UINT num6 = 2654435769U;
		UINT num7 = uD_I32_1[0];
		UINT num8 = uD_I32_1[1];
		UINT num9 = uD_I32_1[2];
		UINT num10 = uD_I32_1[3];
		for (UINT num11 = 0U; num11 < 32U; num11 += 1U)
		{
			num5 += num6;
			num += ((num2 << 4) + num7 ^ num2 + num5 ^ (num2 >> 5) + num8);
			num2 += ((num << 4) + num9 ^ num + num5 ^ (num >> 5) + num10);
			num3 += ((num4 << 4) + num7 ^ num4 + num5 ^ (num4 >> 5) + num8);
			num4 += ((num3 << 4) + num9 ^ num3 + num5 ^ (num3 >> 5) + num10);
		}
		uD_I32_0[0] = num;
		uD_I32_0[1] = num2;
		uD_I32_0[2] = num3;
		uD_I32_0[3] = num4;
	}
	// Token: 0x06002950 RID: 10576 RVA: 0x0026544C File Offset: 0x0026364C
	BOOL DGX_CIOM_Security_5C(const CBinary& ucReqBuff, UINT uReqLen, char uMode, CBinary& binKey)
	{
		UINT array[4] = { 0 };
		if (uReqLen != 4)
		{
			return false;
		}
		for (int i = 0; i < uReqLen; i++)
		{
			array[i] = ucReqBuff[i];
		}
		UINT num = array[3];
		num |= array[2] << 8;
		num |= array[1] << 16;
		num |= array[0] << 24;
		UINT array2[4] = { 0 };
		UINT array3[4] =
		{
			num,
			15794176U,
			16843010U,
			50595078U
		};
		if (uMode == 7)
		{
			array2[0] = 1191274608U;
			array2[1] = 1736868967U;
			array2[2] = 2142376876U;
			array2[3] = 1994170881U;
		}
		else
		{
			if (uMode != 5)
			{
				return false;
			}
			array2[0] = 1191340144U;
			array2[1] = 1736868967U;
			array2[2] = 1804547290U;
			array2[3] = 3754588674U;
		}
		DGX_CIOM_method(array3, array2);
		for (int n = 0; n < 4; ++n)
		{
			binKey.Add((array3[n] >> 24) & 0xFF);
			binKey.Add((array3[n] >> 16) & 0xFF);
			binKey.Add((array3[n] >> 8) & 0xFF);
			binKey.Add(array3[n] & 0xFF);
		}
		return true;
	}

	UINT DFCV_EECU_method(UINT* a1, UINT* a2)
	{
		int v2; // edi
		UINT v3; // esi
		UINT result; // eax
		int v5; // ecx
		int v6; // ebx

		v2 = 0;
		v3 = *a1;
		result = a1[1];
		v5 = a2[1];
		v6 = 0x20;
		do
		{
			v2 -= 0x61C88647;
			v3 += (v2 + result) ^ (*a2 + 0x10 * result) ^ (v5 + (result >> 5));
			v5 = a2[1];
			result += (v2 + v3) ^ (a2[2] + 0x10 * v3) ^ (a2[3] + (v3 >> 5));
			--v6;
		} while (v6);
		*a1 = v3;
		a1[1] = result;
		return result;
	}
	//DFCV_EECU_Security_60(binRecvSeed, 4, 7, binKey);
	BOOL DFCV_EECU_Security_60(const CBinary& ucSeed, CBinary& ucKey, int iMode)
	{
		char v7;
		UINT var24[12] = {0};
		var24[8] = 0;
		var24[4] = 0;
		var24[5] = 0;
		var24[7] = (ucSeed[0] * 16777216 + ucSeed[1] * 65536 + ucSeed[2] * 256 + ucSeed[3]);
		switch (iMode)
		{
		case 3:
			var24[0] = 0xFFEECCAA;
			var24[1] = 0xFFEEEE11;
			var24[2] = 0xFF000011;
			var24[3] = 0xFFCC0055;
			break;
		case 2:
			var24[0] = 0xFFFF00CC;
			var24[1] = 0xFFEEDDFF;
			var24[2] = 0xFFEEEE33;
			var24[3] = 0xFFEEDDFF;
			break;
		case 0x41:
			var24[0] = 0xFFEEEE11;
			var24[1] = 0xFFEE66CC;
			var24[2] = 0xFF000099;
			var24[3] = 0x55666888;
			break;
		}
		DFCV_EECU_method(&var24[7], var24);
		DFCV_EECU_method(&var24[4], var24);
		ucKey.Add((var24[7] >> 24) & 0xFF);
		ucKey.Add((var24[7] >> 16) & 0xFF);
		ucKey.Add((var24[7] >> 8) & 0xFF);
		ucKey.Add(var24[7]);
		ucKey.Add((var24[8] >> 24) & 0xFF);
		ucKey.Add((var24[8] >> 16) & 0xFF);
		ucKey.Add((var24[8] >> 8) & 0xFF);
		ucKey.Add(var24[8] & 0xFF);
		ucKey.Add((var24[5] >> 24) & 0xFF);
		ucKey.Add((var24[5] >> 16) & 0xFF);
		ucKey.Add((var24[5] >> 8) & 0XFF);
		ucKey.Add(var24[5] & 0xFF);
		ucKey.Add((var24[6] >> 24) & 0xFF);
		ucKey.Add((var24[6] >> 16) & 0xFF);
		ucKey.Add((var24[6] >> 8) & 0xFF);
		ucKey.Add(var24[6] & 0xFF);
		return TRUE;
	}

	void SeedToKeyForDFCV_EBP_Mode01(const CBinary& ucSeed, CBinary& ucKey)
	{
		unsigned int uint_0 = (ucSeed[0] << 24) | (ucSeed[1] << 16) | (ucSeed[2] << 8) | ucSeed[3];
		unsigned int num = 0;
		int num2 = 2;
		unsigned int num3 = 3490566157;
		unsigned int arrayData[4] = { 0 };

		arrayData[0] = 1095518031;
		arrayData[1] = 1145783641;
		arrayData[2] = 1093291847;
		arrayData[3] = 1146046025;
		unsigned int num4 = uint_0;
		unsigned int num5 = ~uint_0;

		for (int i = 0; i < num2; i++)
		{
			num4 += (((num5 << 4) ^ (num5 >> 5)) + num5) ^ (num + arrayData[(int)(num & 3)]);
			num += num3;
			num5 += (((num4 << 4) ^ (num4 >> 5)) + num4) ^ (num + arrayData[(int)((num >> 11) & 3)]);
		}
		//ucKey[0] = (num4 >> 24) & 0xFF;
		//ucKey[1] = (num4 >> 16) & 0xFF;
		//ucKey[2] = (num4 >> 8) & 0xFF;
		//ucKey[3] = (num4 >> 0) & 0xFF;
		ucKey.Add((num4 >> 24) & 0xFF);
		ucKey.Add((num4 >> 16) & 0xFF);
		ucKey.Add((num4 >> 8) & 0xFF);
		ucKey.Add((num4 >> 0) & 0xFF);
	}

	void SeedToKeyForDFCV_ABS_VIE(const CBinary& ucSeed, CBinary& ucKey)
	{
		unsigned short num = 0;
		unsigned short num2 = 0;
		unsigned short string_[2] = { 0x257E,0x63A3 };
		unsigned short string_2[2] = { 0x7E52,0x4DC7 };
		unsigned short num3 = ucSeed[0] * 0x100 + ucSeed[1];
		unsigned short num4 = ucSeed[2] * 0x100 + ucSeed[3];
		for (unsigned short num5 = 0; num5 < 5; num5 += 1)
		{
			num2 = num3 ^ ~num4;
			num = (string_[0] * num4 + string_[1]) ^ num3;
			num3 = (unsigned short)((num2 >> 1) ^ (int)string_2[0]);
			num4 = num ^ string_2[1];
		}
		//ucKey[0] = (num2 >> 8) & 0xFF;
		//ucKey[1] = num2 & 0xFF;
		//ucKey[2] = (num >> 8) & 0xFF;
		//ucKey[3] = num & 0xFF;
		ucKey.Add((num2 >> 8) & 0xFF);
		ucKey.Add(num2 & 0xFF);
		ucKey.Add((num >> 8) & 0xFF);
		ucKey.Add(num & 0xFF);
	}

	void SeedToKeyForDFCV_PEPS_Mode03(const CBinary& ucSeed, CBinary& ucKey)
	{
		unsigned short uSeed = ucSeed[0] * 0x100 + ucSeed[1];
		unsigned short uKey = -uSeed - 0x3123;
		//ucKey[0] = uKey >> 8;
		//ucKey[1] = uKey & 0xFF;
		ucKey.Add(uKey >> 8);
		ucKey.Add(uKey & 0xFF);
	}
	void SeedToKeyForDFCV_DFCV_AMT2_Mode01(const CBinary& ucSeed, CBinary& ucKey)
	{
		unsigned int uint_0[] = { 4077348590, 3688210568, 3495442853, 3532337479, 64 };

		unsigned int num = (unsigned int)ucSeed[0];
		num <<= 8;
		num += (unsigned int)ucSeed[1];
		num <<= 8;
		num += (unsigned int)ucSeed[2];
		num <<= 8;
		num += (unsigned int)ucSeed[3];
		unsigned int num2 = (unsigned int)ucSeed[4];
		num2 <<= 8;
		num2 += (unsigned int)ucSeed[5];
		num2 <<= 8;
		num2 += (unsigned int)ucSeed[6];
		num2 <<= 8;
		num2 += (unsigned int)ucSeed[7];
		unsigned short num3 = (unsigned short)uint_0[4];
		unsigned int num4 = 0;
		for (unsigned short num5 = 0; num5 < num3; num5 += 1)
		{
			num += (((num2 << 4) ^ (num2 >> 5)) + num2) ^ (num4 + uint_0[(int)(num4 & 3)]);
			num4 += 2654435769U;
			num2 += (((num << 4) ^ (num >> 5)) + num) ^ (num4 + uint_0[(int)((num4 >> 11) & 3)]);
		}
		//ucKey[3] = (unsigned char)(num & 255);
		//num >>= 8;
		//ucKey[2] = (unsigned char)(num & 255);
		//num >>= 8;
		//ucKey[1] = (unsigned char)(num & 255);
		//num >>= 8;
		//ucKey[0] = (unsigned char)(num & 255);
		//ucKey[7] = (unsigned char)(num2 & 255);
		//num2 >>= 8;
		//ucKey[6] = (unsigned char)(num2 & 255);
		//num2 >>= 8;
		//ucKey[5] = (unsigned char)(num2 & 255);
		//num2 >>= 8;
		//ucKey[4] = (unsigned char)(num2 & 255);

		ucKey.Add((num >> 24) & 0xFF);
		ucKey.Add((num >> 16) & 0xFF);
		ucKey.Add((num >> 8) & 0xFF);
		ucKey.Add(num & 0xFF);
		ucKey.Add((num2 >> 24) & 0xFF);
		ucKey.Add((num2 >> 16) & 0xFF);
		ucKey.Add((num2 >> 8) & 0xFF);
		ucKey.Add(num2 & 0xFF);
	}

	void SeedToKeyForDFCV_YZS_AEBS_R(const CBinary& ucSeed, CBinary& ucKey)
	{
		unsigned char v7 = ucSeed[1] ^ 0x68;
		unsigned char v8 = ucSeed[2] ^ 0x87;
		//unsigned char v9 = (0x10 * v7) | ((char)(*ucSeed ^ 0x76) >> 4) & 0xF;
		unsigned char v9 = (0x10 * v7) | ((ucSeed[0] ^ 0x76) >> 4) & 0xF;
		unsigned char v10 = v7 ^ (v7 ^ (v8 >> 4)) & 0xF;
		//ucKey[3] = (0x10 * (*ucSeed ^ 0x76)) | v8 & 0xF;
		//ucKey[2] = v10;
		//ucKey[1] = v9;
		//ucKey[0] = (ucSeed[3] ^ 0x83) & 0xF0 | (0x10 * (ucSeed[3] ^ 0x83));
		ucKey.Add((ucSeed[3] ^ 0x83) & 0xF0 | (0x10 * (ucSeed[3] ^ 0x83)));
		ucKey.Add(v9);
		ucKey.Add(v10);
		ucKey.Add((0x10 * (ucSeed[0] ^ 0x76)) | v8 & 0xF);
	}

	void SeedToKeyForDFCV_KT1B_TCU(const CBinary& ucSeed, CBinary& ucKey)
	{
		unsigned short num = 65534;
		for (unsigned char b = 0; b < 2; b += 1)
		{
			num ^= (unsigned short)(ucSeed[(int)b] << 8);
			for (unsigned char b2 = 0; b2 < 8; b2 += 1)
			{
				if ((num & 32768) != 0)
				{
					if ((num & 128) != 0)
					{
						num = (unsigned short)(((int)num << 1) ^ 33800);
					}
					else
					{
						num = (unsigned short)(((int)num << 1) ^ 32805);
					}
				}
				else
				{
					num = (unsigned short)(num << 1);
				}
			}
		}
		//ucKey[0] = (num >> 8) & 0xFF;
		//ucKey[1] = num & 0xFF;
		ucKey.Add((num >> 8) & 0xFF);
		ucKey.Add(num & 0xFF);
	}

	unsigned int sub_10001130(unsigned int* a1, unsigned int* a2)
	{
		unsigned int v2;	unsigned int v3;	int v4;	unsigned int v5;	unsigned int v6;
		int v7;	int v8;	int v9;	int v10;	int v11;	int v12;	int v13;	int v14;	int v15;	int v16;	int v17;	int v18;	int v19;	int v20;	int v21;	int v22;	int v23;	int v24;	int v25;	int v26;	int v27;	int v28;	int v29;	int v30;	int v31;	int v32;	int v33;	int v34;	int v35;	int v36;
		int v37;	int v38;	int v39;	int v40;	int v41;	int v42;	int v43;	int v44;	int v45;	int v46;	int v47;	int v48;	int v49;	int v50;	int v51;	int v52;	int v53;	int v54;	int v55;	int v56;	int v57;	int v58;	int v59;	int v60;	int v61;	int v62;	int v63;	int v64;	int v65;	int v66;
		int v67;	int v68;	int v69;	int v70;	int v71;	int v72;	int v73;	int v74;	int v75;	int v76;	int v77;	int v78;	unsigned int v79;	int v80;	int v81;	int v82;	int v83;	int v84;	int v85;	int v86;	int v87;	int v88;	int v89;	int v90;	int v91;	int v92;	int v93;	int v94;	int v95;
		int v96;	int v97;	int v98;	int v99;	int v100;	int v101;	int v102;	int v103;	int v104;	int v105;	int v106;	int v107;	int v108;	int v109;	int v110;	int v111;	int v112;	int v113;	int v114;	int v115;	int v116;	int v117;	int v118;	int v119;	int v120;	int v121;	int v122;	int v123;	int v124;	int v125;
		int v126;	int v127;	int v128;	int v129;	int v130;	int v131;	int v132;	int v133;	int v134;	int v135;	int v136;	int v137;	int v138;	int v139;	int v140;	int v141;	int v142;	int v143;	int v144;	int v145;	int v146;	int v147;	int v148;	int v149;	int v150;	int v151;	int v152;	int v153;	int v154;	int v155;	int v156;	int v157;	int v158;	int v159;	int v160;	int v161;	int v162;	int v163;	int v164;	int v165;	int v166;	int v167;	int v168;	int v169;	int v170;	int v171;	int v172;	int v173;	int v174;	int v175;	int v176;	int v177;	int v178;	int v179;	int v180;	int v181;	int v182;	int v183;	int v184;	int v185;	int v186;	int v187;	int v188;	int v189;	int v190;	int v191;	int v192;	int v193;	int v194;	int v195;	int v196;	int v197;	int v198;	int v199;	int v200;	int v201;	int v202;	int v203;	int v204;	int v205;	int v206;	int v207;	int v208;	int v209;	int v210;	int v211;	int v212;	int v213;	int v214;	unsigned int v215;	unsigned int v216;	unsigned int v217;	unsigned int v218;	int v219;	unsigned int v220;	unsigned int v221;	int v222;	int v223;	unsigned int v224;	int v225;	int v226;	int v227;	int v228;	int v229;	int v230;	int v231;	int v232;	int v233;	int v234;	int v235;	int v236;	int v237;	int v238;	int v239;	int v240;	int v241;	int v242;	int v243;	int v244;
		int v245;	int v246;	int v247;	int v248;	int v249;	int v250;	int v251;	int v252;	int v253;	int v254;	int v255;	int v256;	int v257;	int v258;	int v259;	int v260;	int v261;	int v262;	int v263;	int v264;	int v265;	int v266;	int v267;	int v268;	int v269;	int v270;	int v271;	int v272;	int v273;	int v274;	int v275;	int v276;	int v277;	int v278;	int v279;	int v280;	int v281;	int v282;	int v283;	int v284;	int v285;	int v286;	int v287;	int v288;	int v289;	int v290;	int v291;	int v292;	int v293;	int v294;	int v295;	int v296;	int v297;	int v298;	int v299;	int v300;	int v301;	int v302;	int v303;	int v304;	int v305;	int v306;	int v307;	int v308;	int v309;	int v310;	int v311;	int v312;	int v313;	int v314;	int v315;	int v316;	int v317;	int v318;	int v319;	int v320;	int v321;	int v322;	int v323;	int v324;	int v325;	int v326;	int v327;	int v328;	int v329;	int v330;	int v331;	int v332;	int v333;	int v334;	int v335;	int v336;	int v337;	int v338;	int v339;	int v340;	int v341;	int v342;	int v343;	int v344;	int v345;	int v346;	int v347;	int v348;	int v349;	int v350;	int v351;	int v352;	int v353;	int v354;	int v355;	int v356;	int v357;	int v358;	int v359;	int v360;	int v361;	int v362;	int v363;	int v364;	int v365;	int v366;	int v367;	int v368;	int v369;	int v370;	int v371;	int v372;	int v373;	int v374;	int v375;	int v376;	int v377;	int v378;	int v379;	int v380;	int v381;	int v382;	int v383;	int v384;	int v385;	int v386;	int v387;	int v388;	int v389;	int v390;	int v391;	int v392;	int v393;	int v394;	int v395;	int v396;	int v397;	int v398;	int v399;	int v400;	int v401;	int v402;	int v403;	int v404;
		int v405;	int v406;	int v407;	int v408;	int v409;	int v410;	int v411;	int v412;	int v413;	int v414;	int v415;	int v416;	int v417;	int v418;	int v419;	int v420;	int v421;	int v422;	int v423;	int v424;	int v425;	int v426;	int v427;	int v428;	int v429;	int v430;	int v431;	int v432;	unsigned int v433;	unsigned int result;	int v435;	int v436;	int v437;	int v438;	int v439;	int v440;	int v441;	int v442;	int v443;	int v444;	int v445;	int v446;	int v447;	int v448;	int v449;	int v450;	int v451;	int v452;	int v453;	int v454;	int v455;	int v456;	int v457;	int v458;	int v459;	int v460;	int v461;	int v462;	int v463;	int v464;	int v465;	int v466;	int v467;	int v468;	int v469;	int v470;	int v471;	int v472;	int v473;	int v474;	int v475;	int v476;	int v477;	int v478;	int v479;	int v480;	int v481;	int v482;	int v483;	int v484;	int v485;	int v486;	int v487;	int v488;	int v489;	int v490;	int v491;	int v492;	int v493;	int v494;	int v495;	int v496;	unsigned int v498;	unsigned int v499;	unsigned int v500;	unsigned int v501;	unsigned int v502;	unsigned int v503;	unsigned int v504;	unsigned int v505;	unsigned int v506;	unsigned int v507;	unsigned int v508;	unsigned int v509;	unsigned int v510;	unsigned int v511;	unsigned int v512;	unsigned int v514;
		v2 = a1[2];
		v3 = a1[1];
		v498 = *a2;
		v4 = __ROL4__(v2, 0xA);
		v5 = a1[4] + __ROL4__(*a1 + *a2 + (v3 ^ v2 ^ a1[3]), 0xB);
		v500 = a2[1];
		v6 = a1[3] + __ROL4__(a1[4] + v500 + (v5 ^ v3 ^ v4), 0xE);
		v7 = __ROL4__(v3, 0xA);
		v499 = a2[2];
		v8 = v5 ^ v7 ^ v6;
		v9 = __ROL4__(v5, 0xA);
		v10 = v4 + __ROL4__(a1[3] + v499 + v8, 0xF);
		v504 = a2[3];
		v11 = v10 ^ v6;
		v12 = __ROL4__(v6, 0xA);
		v13 = v7 + __ROL4__(v4 + v504 + (v9 ^ v11), 0xC);
		v510 = a2[4];
		v14 = v10 ^ v12;
		v15 = __ROL4__(v10, 0xA);
		v16 = v9 + __ROL4__(v7 + v510 + (v13 ^ v14), 5);
		v509 = a2[5];
		v17 = v12 + __ROL4__(v9 + v509 + (v16 ^ v13 ^ v15), 8);
		v18 = __ROL4__(v13, 0xA);
		v506 = a2[6];
		v19 = v16 ^ v18;
		v20 = __ROL4__(v16, 0xA);
		v21 = v15 + __ROL4__(v12 + v506 + (v17 ^ v19), 7);
		v507 = a2[7];
		v22 = v17 ^ v20 ^ v21;
		v23 = __ROL4__(v17, 0xA);
		v24 = v18 + __ROL4__(v15 + v507 + v22, 9);
		v508 = a2[8];
		v25 = v24 ^ v21;
		v26 = __ROL4__(v21, 0xA);
		v27 = v20 + __ROL4__(v18 + v508 + (v23 ^ v25), 0xB);
		v503 = a2[9];
		v28 = v24 ^ v26;
		v29 = __ROL4__(v24, 0xA);
		v30 = v23 + __ROL4__(v20 + v503 + (v27 ^ v28), 0xD);
		v511 = a2[0xA];
		v31 = v27 ^ v29;
		v32 = __ROL4__(v27, 0xA);
		v33 = v26 + __ROL4__(v23 + v511 + (v30 ^ v31), 0xE);
		v502 = a2[0xB];
		v34 = v30 ^ v32;
		v35 = __ROL4__(v30, 0xA);
		v36 = v29 + __ROL4__(v26 + v502 + (v33 ^ v34), 0xF);
		v512 = a2[0xC];
		v37 = v33 ^ v35 ^ v36;
		v38 = __ROL4__(v33, 0xA);
		v39 = v32 + __ROL4__(v29 + v512 + v37, 6);
		v501 = a2[0xD];
		v40 = v35 + __ROL4__(v32 + v501 + (v38 ^ v39 ^ v36), 7);
		v436 = __ROL4__(v36, 0xA);
		v505 = a2[0xE];
		v41 = v39 ^ v436;
		v42 = __ROL4__(v39, 0xA);
		v43 = __ROL4__(v35 + v505 + (v40 ^ v41), 9);
		v442 = v38 + v43;
		v514 = a2[0xF];
		v44 = v40 ^ v42;
		v45 = __ROL4__(v40, 0xA);
		v46 = v436 + __ROL4__(v38 + v514 + ((v38 + v43) ^ v44), 8);
		v47 = v46 & (v38 + v43);
		v481 = v46;
		v48 = v46;
		v49 = __ROL4__(v442, 0xA);
		v50 = v42 + __ROL4__(v507 + (v47 | v45 & ~v48) + v436 + 0x5A827999, 7);
		v51 = v510 + (v481 & v50 | v49 & ~v50) + 0x5A827999 + v42;
		v482 = __ROL4__(v481, 0xA);
		v52 = v45 + __ROL4__(v51, 6);
		v53 = v52 & v50;
		v54 = __ROL4__(v50, 0xA);
		v55 = v49 + __ROL4__(v501 + (v53 | v482 & ~v52) + 0x5A827999 + v45, 8);
		v56 = v482 + __ROL4__(v500 + (v55 & v52 | v54 & ~v55) + v49 + 0x5A827999, 0xD);
		v57 = __ROL4__(v52, 0xA);
		v58 = v56 & v55;
		v59 = __ROL4__(v55, 0xA);
		v455 = v54 + __ROL4__(v511 + (v58 | v57 & ~v56) + v482 + 0x5A827999, 0xB);
		v60 = v455 & v56 | v59 & ~v455;
		v61 = __ROL4__(v56, 0xA);
		v62 = __ROL4__(v506 + v60 + v54 + 0x5A827999, 9);
		v437 = v57 + v62;
		v63 = __ROL4__(v455, 0xA);
		v64 = __ROL4__(v514 + (v455 & (v57 + v62) | v61 & ~(v57 + v62)) + v57 + 0x5A827999, 7);
		v456 = v59 + v64;
		v65 = __ROL4__(v437, 0xA);
		v66 = __ROL4__(v504 + ((v59 + v64) & v437 | v63 & ~(v59 + v64)) + v59 + 0x5A827999, 0xF);
		v463 = v61 + v66;
		v67 = __ROL4__(v456, 0xA);
		v68 = __ROL4__(v512 + ((v61 + v66) & v456 | v65 & ~(v61 + v66)) + v61 + 0x5A827999, 7);
		v457 = v63 + v68;
		v69 = __ROL4__(v498 + ((v63 + v68) & v463 | v67 & ~(v63 + v68)) + v63 + 0x5A827999, 0xC);
		v483 = v65 + v69;
		v70 = __ROL4__(v463, 0xA);
		v71 = __ROL4__(v457, 0xA);
		v72 = v503 + ((v65 + v69) & v457 | v70 & ~(v65 + v69)) + v65 + 0x5A827999;
		v73 = v67 + 0x5A827999;
		v74 = v67 + __ROL4__(v72, 0xF);
		v75 = v70 + 0x5A827999;
		v76 = v70 + __ROL4__(v509 + (v483 & v74 | v71 & ~v74) + v73, 9);
		v77 = __ROL4__(v483, 0xA);
		v78 = v71 + __ROL4__(v499 + (v76 & v74 | v77 & ~v76) + v75, 0xB);
		v468 = __ROL4__(v74, 0xA);
		v438 = __ROL4__(v76, 0xA);
		v79 = v505 + (v78 & v76 | v468 & ~v78);
		v80 = v78;
		v81 = __ROL4__(v78, 0xA);
		v82 = v77 + __ROL4__(v79 + v71 + 0x5A827999, 7);
		v83 = v468 + __ROL4__(v502 + (v82 & v80 | v438 & ~v82) + v77 + 0x5A827999, 0xD);
		v84 = ~v83;
		v85 = v438 + __ROL4__(v468 + 0x5A827999 + v508 + (v83 & v82 | v81 & ~v83), 0xC);
		v86 = __ROL4__(v82, 0xA);
		v87 = __ROL4__(v83, 0xA);
		v88 = ~v85;
		v89 = v81 + __ROL4__(v438 + 0x6ED9EBA1 + v504 + (v86 ^ (v85 | v84)), 0xB);
		v90 = __ROL4__(v85, 0xA);
		v91 = v511 + (v87 ^ (v89 | v88)) + 0x6ED9EBA1 + v81;
		v92 = ~v89;
		v93 = v86 + __ROL4__(v91, 0xD);
		v94 = __ROL4__(v89, 0xA);
		v95 = v505 + (v90 ^ (v93 | v92)) + 0x6ED9EBA1 + v86;
		v96 = ~v93;
		v97 = v87 + __ROL4__(v95, 6);
		v98 = __ROL4__(v93, 0xA);
		v99 = v510 + (v94 ^ (v97 | v96)) + 0x6ED9EBA1 + v87;
		v100 = ~v97;
		v101 = v90 + __ROL4__(v99, 7);
		v102 = __ROL4__(v97, 0xA);
		v103 = v503 + (v98 ^ (v101 | v100)) + 0x6ED9EBA1 + v90;
		v104 = ~v101;
		v105 = v94 + __ROL4__(v103, 0xE);
		v106 = __ROL4__(v101, 0xA);
		v107 = v514 + (v102 ^ (v105 | v104)) + 0x6ED9EBA1 + v94;
		v108 = ~v105;
		v109 = v98 + __ROL4__(v107, 9);
		v110 = __ROL4__(v105, 0xA);
		v111 = v102 + __ROL4__(v508 + (v106 ^ (v109 | v108)) + 0x6ED9EBA1 + v98, 0xD);
		v112 = v106 + __ROL4__(v500 + (v110 ^ (v111 | ~v109)) + 0x6ED9EBA1 + v102, 0xF);
		v113 = __ROL4__(v109, 0xA);
		v114 = ~v111;
		v115 = __ROL4__(v111, 0xA);
		v116 = v499 + (v113 ^ (v112 | v114)) + 0x6ED9EBA1 + v106;
		v117 = ~v112;
		v118 = v110 + __ROL4__(v116, 0xE);
		v119 = __ROL4__(v112, 0xA);
		v120 = v507 + (v115 ^ (v118 | v117)) + 0x6ED9EBA1 + v110;
		v121 = ~v118;
		v122 = v113 + __ROL4__(v120, 8);
		v123 = __ROL4__(v118, 0xA);
		v124 = v498 + (v119 ^ (v122 | v121)) + 0x6ED9EBA1 + v113;
		v125 = ~v122;
		v126 = v115 + __ROL4__(v124, 0xD);
		v127 = __ROL4__(v122, 0xA);
		v128 = v506 + (v123 ^ (v126 | v125)) + 0x6ED9EBA1 + v115;
		v129 = ~v126;
		v130 = v119 + __ROL4__(v128, 6);
		v131 = __ROL4__(v126, 0xA);
		v132 = v501 + (v127 ^ (v130 | v129)) + 0x6ED9EBA1 + v119;
		v133 = ~v130;
		v134 = v123 + __ROL4__(v132, 5);
		v135 = __ROL4__(v130, 0xA);
		v136 = v502 + (v131 ^ (v134 | v133)) + 0x6ED9EBA1 + v123;
		v137 = ~v134;
		v138 = v127 + __ROL4__(v136, 0xC);
		v139 = __ROL4__(v134, 0xA);
		v140 = v131 + __ROL4__(v509 + (v135 ^ (v138 | v137)) + 0x6ED9EBA1 + v127, 7);
		v141 = __ROL4__(v131 + 0x6ED9EBA1 + v512 + (v139 ^ (v140 | ~v138)), 5);
		v142 = __ROL4__(v138, 0xA);
		v443 = v135 + v141;
		v143 = __ROL4__(v140, 0xA);
		v144 = __ROL4__(v500 + (v142 & (v135 + v141) | v140 & ~v142) + v135 - 0x70E44324, 0xB);
		v458 = v139 + v144;
		v145 = __ROL4__(v443, 0xA);
		v146 = __ROL4__(v139 + v503 + (v443 & ~v143 | (v139 + v144) & v143) - 0x70E44324, 0xC);
		v147 = __ROL4__(v458, 0xA);
		v464 = v142 + v146;
		v148 = __ROL4__(v142 + v502 + (v458 & ~v145 | (v142 + v146) & v145) - 0x70E44324, 0xE);
		v149 = __ROL4__(v464, 0xA);
		v459 = v143 + v148;
		v150 = __ROL4__(v511 + ((v143 + v148) & v147 | v464 & ~v147) + v143 - 0x70E44324, 0xF);
		v439 = v145 + v150;
		v151 = __ROL4__(v459, 0xA);
		v152 = __ROL4__(v498 + (v149 & (v145 + v150) | v459 & ~v149) + v145 - 0x70E44324, 0xE);
		v444 = v147 + v152;
		v153 = __ROL4__(v508 + (v151 & (v147 + v152) | v439 & ~v151) + v147 - 0x70E44324, 0xF);
		v154 = __ROL4__(v439, 0xA);
		v460 = v149 + v153;
		v155 = __ROL4__(v444, 0xA);
		v156 = __ROL4__(v512 + ((v149 + v153) & v154 | v444 & ~v154) + v149 - 0x70E44324, 9);
		v465 = v151 + v156;
		v157 = __ROL4__(v460, 0xA);
		v158 = __ROL4__(v510 + ((v151 + v156) & v155 | v460 & ~v155) + v151 - 0x70E44324, 8);
		v461 = v154 + v158;
		v159 = __ROL4__(v465, 0xA);
		v160 = __ROL4__(v501 + ((v154 + v158) & v157 | v465 & ~v157) + v154 - 0x70E44324, 9);
		v440 = v155 + v160;
		v161 = __ROL4__(v461, 0xA);
		v162 = __ROL4__(v504 + (v159 & (v155 + v160) | v461 & ~v159) + v155 - 0x70E44324, 0xE);
		v445 = v157 + v162;
		v163 = __ROL4__(v440, 0xA);
		v164 = __ROL4__(v507 + (v161 & (v157 + v162) | v440 & ~v161) + v157 - 0x70E44324, 5);
		v484 = v159 + v164;
		v165 = v161 + __ROL4__(v514 + ((v159 + v164) & v163 | v445 & ~v163) + v159 - 0x70E44324, 6);
		v166 = __ROL4__(v445, 0xA);
		v167 = __ROL4__(v484, 0xA);
		v168 = v165 & ~v167;
		v169 = v163 + __ROL4__(v505 + (v165 & v166 | v484 & ~v166) + v161 - 0x70E44324, 8);
		v170 = __ROL4__(v165, 0xA);
		v171 = v166 + __ROL4__(v509 + (v169 & v167 | v168) + v163 - 0x70E44324, 6);
		v172 = v169 & ~v170;
		v173 = __ROL4__(v169, 0xA);
		v174 = v167 + __ROL4__(v506 + (v170 & v171 | v172) + v166 - 0x70E44324, 5);
		v175 = v171 & ~v173;
		v176 = __ROL4__(v171, 0xA);
		v177 = v170 + __ROL4__(v167 - 0x70E44324 + v499 + (v173 & v174 | v175), 0xC);
		v178 = v177 ^ (v174 | ~v176);
		v179 = __ROL4__(v174, 0xA);
		v180 = v173 + __ROL4__(v510 + v178 - 0x56AC02B2 + v170, 9);
		v181 = v180 ^ (v177 | ~v179);
		v182 = __ROL4__(v177, 0xA);
		v183 = v176 + __ROL4__(v498 + v181 - 0x56AC02B2 + v173, 0xF);
		v184 = v179 + __ROL4__(v509 + (v183 ^ (v180 | ~v182)) - 0x56AC02B2 + v176, 5);
		v185 = __ROL4__(v180, 0xA);
		v186 = v183 | ~v185;
		v187 = __ROL4__(v183, 0xA);
		v188 = v182 + __ROL4__(v503 + (v184 ^ v186) - 0x56AC02B2 + v179, 0xB);
		v189 = v188 ^ (v184 | ~v187);
		v190 = __ROL4__(v184, 0xA);
		v191 = v185 + __ROL4__(v507 + v189 - 0x56AC02B2 + v182, 6);
		v192 = v191 ^ (v188 | ~v190);
		v193 = __ROL4__(v188, 0xA);
		v194 = v187 + __ROL4__(v512 + v192 - 0x56AC02B2 + v185, 8);
		v195 = v194 ^ (v191 | ~v193);
		v196 = __ROL4__(v191, 0xA);
		v197 = v190 + __ROL4__(v499 + v195 - 0x56AC02B2 + v187, 0xD);
		v198 = v197 ^ (v194 | ~v196);
		v199 = __ROL4__(v194, 0xA);
		v200 = v193 + __ROL4__(v511 + v198 - 0x56AC02B2 + v190, 0xC);
		v201 = v200 ^ (v197 | ~v199);
		v202 = __ROL4__(v197, 0xA);
		v203 = v196 + __ROL4__(v505 + v201 - 0x56AC02B2 + v193, 5);
		v204 = v203 ^ (v200 | ~v202);
		v205 = __ROL4__(v200, 0xA);
		v206 = v199 + __ROL4__(v500 + v204 - 0x56AC02B2 + v196, 0xC);
		v207 = __ROL4__(v504 + (v206 ^ (v203 | ~v205)) - 0x56AC02B2 + v199, 0xD);
		v208 = __ROL4__(v203, 0xA);
		v466 = v202 + v207;
		v209 = v206 | ~v208;
		v210 = __ROL4__(v206, 0xA);
		v211 = v205 + __ROL4__(v508 + ((v202 + v207) ^ v209) + v202 - 0x56AC02B2, 0xE);
		v212 = __ROL4__(v502 + (v211 ^ (v466 | ~v210)) + v205 - 0x56AC02B2, 0xB);
		v467 = __ROL4__(v466, 0xA);
		v213 = v208 + v212;
		v462 = __ROL4__(v211, 0xA);
		v214 = __ROL4__(v506 + (v213 ^ (v211 | ~v467)) + v208 - 0x56AC02B2, 8);
		v435 = __ROL4__(v213, 0xA);
		v446 = v210 + v214;
		v441 = v467 + __ROL4__(v210 - 0x56AC02B2 + v514 + ((v210 + v214) ^ (v213 | ~v462)), 5);
		v215 = a1[3];
		v216 = a1[2];
		v217 = a1[1];
		v218 = v509 + (v217 ^ (v216 | ~v215)) + *a1 + 0x50A28BE6;
		v219 = __ROL4__(v216, 0xA);
		v220 = a1[4];
		v221 = v220 + __ROL4__(v218, 8);
		v222 = v217 | ~v219;
		v223 = __ROL4__(v217, 0xA);
		v224 = v215 + __ROL4__(v505 + (v221 ^ v222) + v220 + 0x50A28BE6, 9);
		v225 = v219 + __ROL4__(v507 + (v224 ^ (v221 | ~v223)) + v215 + 0x50A28BE6, 9);
		v226 = __ROL4__(v221, 0xA);
		v227 = v224 | ~v226;
		v228 = __ROL4__(v224, 0xA);
		v229 = v223 + __ROL4__(v498 + (v225 ^ v227) + v219 + 0x50A28BE6, 0xB);
		v230 = v229 ^ (v225 | ~v228);
		v231 = __ROL4__(v225, 0xA);
		v232 = v226 + __ROL4__(v503 + v230 + v223 + 0x50A28BE6, 0xD);
		v233 = v232 ^ (v229 | ~v231);
		v234 = __ROL4__(v229, 0xA);
		v235 = v228 + __ROL4__(v499 + v233 + 0x50A28BE6 + v226, 0xF);
		v236 = v235 ^ (v232 | ~v234);
		v237 = __ROL4__(v232, 0xA);
		v238 = v231 + __ROL4__(v502 + v236 + 0x50A28BE6 + v228, 0xF);
		v239 = v238 ^ (v235 | ~v237);
		v240 = __ROL4__(v235, 0xA);
		v241 = v234 + __ROL4__(v510 + v239 + 0x50A28BE6 + v231, 5);
		v242 = v241 ^ (v238 | ~v240);
		v243 = __ROL4__(v238, 0xA);
		v244 = v237 + __ROL4__(v501 + v242 + 0x50A28BE6 + v234, 7);
		v245 = v244 ^ (v241 | ~v243);
		v246 = __ROL4__(v241, 0xA);
		v247 = v240 + __ROL4__(v506 + v245 + 0x50A28BE6 + v237, 7);
		v248 = v243 + __ROL4__(v514 + (v247 ^ (v244 | ~v246)) + 0x50A28BE6 + v240, 8);
		v249 = __ROL4__(v244, 0xA);
		v250 = v247 | ~v249;
		v251 = __ROL4__(v247, 0xA);
		v252 = v246 + __ROL4__(v508 + (v248 ^ v250) + 0x50A28BE6 + v243, 0xB);
		v253 = v252 ^ (v248 | ~v251);
		v254 = __ROL4__(v248, 0xA);
		v255 = v249 + __ROL4__(v500 + v253 + 0x50A28BE6 + v246, 0xE);
		v256 = v255 ^ (v252 | ~v254);
		v257 = __ROL4__(v252, 0xA);
		v258 = v251 + __ROL4__(v511 + v256 + 0x50A28BE6 + v249, 0xE);
		v259 = v258 ^ (v255 | ~v257);
		v260 = __ROL4__(v255, 0xA);
		v261 = v254 + __ROL4__(v504 + v259 + 0x50A28BE6 + v251, 0xC);
		v262 = v261 ^ (v258 | ~v260);
		v447 = __ROL4__(v258, 0xA);
		v469 = v261;
		v263 = v261 & ~v447;
		v264 = v447;
		v485 = v257 + __ROL4__(v512 + v262 + 0x50A28BE6 + v254, 6);
		v265 = __ROL4__(v469, 0xA);
		v266 = __ROL4__(v506 + (v485 & v447 | v263) + v257 + 0x5C4DD124, 9);
		v448 = v260 + v266;
		v267 = __ROL4__(v502 + (v265 & (v260 + v266) | v485 & ~v265) + v260 + 0x5C4DD124, 0xD);
		v268 = __ROL4__(v485, 0xA);
		v486 = v264 + v267;
		v269 = __ROL4__(v448, 0xA);
		v270 = __ROL4__(v504 + (v268 & (v264 + v267) | v448 & ~v268) + v264 + 0x5C4DD124, 0xF);
		v470 = v265 + v270;
		v271 = __ROL4__(v486, 0xA);
		v272 = __ROL4__(v507 + ((v265 + v270) & v269 | v486 & ~v269) + v265 + 0x5C4DD124, 7);
		v487 = v268 + v272;
		v273 = __ROL4__(v470, 0xA);
		v274 = __ROL4__(v498 + ((v268 + v272) & v271 | v470 & ~v271) + v268 + 0x5C4DD124, 0xC);
		v471 = v269 + v274;
		v275 = __ROL4__(v487, 0xA);
		v276 = __ROL4__(v501 + ((v269 + v274) & v273 | v487 & ~v273) + v269 + 0x5C4DD124, 8);
		v449 = v271 + v276;
		v277 = __ROL4__(v471, 0xA);
		v278 = __ROL4__(v509 + (v275 & (v271 + v276) | v471 & ~v275) + v271 + 0x5C4DD124, 9);
		v488 = v273 + v278;
		v279 = __ROL4__(v511 + (v277 & (v273 + v278) | v449 & ~v277) + v273 + 0x5C4DD124, 0xB);
		v280 = __ROL4__(v449, 0xA);
		v472 = v275 + v279;
		v281 = __ROL4__(v488, 0xA);
		v282 = __ROL4__(v505 + ((v275 + v279) & v280 | v488 & ~v280) + v275 + 0x5C4DD124, 7);
		v489 = v277 + v282;
		v283 = __ROL4__(v472, 0xA);
		v473 = v280 + __ROL4__(v514 + ((v277 + v282) & v281 | v472 & ~v281) + v277 + 0x5C4DD124, 7);
		v284 = __ROL4__(v277 + v282, 0xA);
		v490 = v281 + __ROL4__(v508 + (v473 & v283 | v489 & ~v283) + v280 + 0x5C4DD124, 0xC);
		v285 = v512 + (v284 & v490 | v473 & ~v284) + v281 + 0x5C4DD124;
		v474 = __ROL4__(v473, 0xA);
		v286 = v283 + __ROL4__(v285, 7);
		v287 = __ROL4__(v490, 0xA);
		v288 = v284 + __ROL4__(v510 + (v474 & v286 | v490 & ~v474) + v283 + 0x5C4DD124, 6);
		v289 = v474 + __ROL4__(v503 + (v288 & v287 | v286 & ~v287) + v284 + 0x5C4DD124, 0xF);
		v290 = __ROL4__(v286, 0xA);
		v291 = v289 & v290 | v288 & ~v290;
		v292 = __ROL4__(v288, 0xA);
		v293 = v287 + __ROL4__(v500 + v291 + v474 + 0x5C4DD124, 0xD);
		v294 = v289 & ~v292;
		v295 = __ROL4__(v289, 0xA);
		v296 = v287 + 0x5C4DD124 + v499 + (v293 & v292 | v294);
		v297 = ~v293;
		v298 = v290 + __ROL4__(v296, 0xB);
		v299 = __ROL4__(v293, 0xA);
		v300 = v514 + (v295 ^ (v298 | v297)) + 0x6D703EF3 + v290;
		v301 = ~v298;
		v302 = v292 + __ROL4__(v300, 9);
		v303 = __ROL4__(v298, 0xA);
		v304 = v509 + (v299 ^ (v302 | v301)) + 0x6D703EF3 + v292;
		v305 = ~v302;
		v306 = v295 + __ROL4__(v304, 7);
		v307 = __ROL4__(v302, 0xA);
		v308 = v500 + (v303 ^ (v306 | v305)) + 0x6D703EF3 + v295;
		v309 = ~v306;
		v310 = v299 + __ROL4__(v308, 0xF);
		v311 = __ROL4__(v306, 0xA);
		v312 = v504 + (v307 ^ (v310 | v309)) + 0x6D703EF3 + v299;
		v313 = ~v310;
		v314 = v303 + __ROL4__(v312, 0xB);
		v315 = __ROL4__(v310, 0xA);
		v316 = v307 + __ROL4__(v507 + (v311 ^ (v314 | v313)) + 0x6D703EF3 + v303, 8);
		v317 = v505 + (v315 ^ (v316 | ~v314)) + 0x6D703EF3 + v307;
		v318 = __ROL4__(v314, 0xA);
		v319 = ~v316;
		v320 = __ROL4__(v316, 0xA);
		v321 = v311 + __ROL4__(v317, 6);
		v322 = v506 + (v318 ^ (v321 | v319)) + 0x6D703EF3 + v311;
		v323 = ~v321;
		v324 = v315 + __ROL4__(v322, 6);
		v325 = __ROL4__(v321, 0xA);
		v326 = v503 + (v320 ^ (v324 | v323)) + 0x6D703EF3 + v315;
		v327 = ~v324;
		v328 = v318 + __ROL4__(v326, 0xE);
		v329 = __ROL4__(v324, 0xA);
		v330 = v502 + (v325 ^ (v328 | v327)) + 0x6D703EF3 + v318;
		v331 = ~v328;
		v332 = v320 + __ROL4__(v330, 0xC);
		v333 = __ROL4__(v328, 0xA);
		v334 = v508 + (v329 ^ (v332 | v331)) + 0x6D703EF3 + v320;
		v335 = ~v332;
		v336 = v325 + __ROL4__(v334, 0xD);
		v337 = __ROL4__(v332, 0xA);
		v338 = v512 + (v333 ^ (v336 | v335)) + 0x6D703EF3 + v325;
		v339 = ~v336;
		v340 = v329 + __ROL4__(v338, 5);
		v341 = __ROL4__(v336, 0xA);
		v342 = v499 + (v337 ^ (v340 | v339)) + 0x6D703EF3 + v329;
		v343 = ~v340;
		v344 = v333 + __ROL4__(v342, 0xE);
		v345 = __ROL4__(v340, 0xA);
		v346 = v337 + __ROL4__(v511 + (v341 ^ (v344 | v343)) + 0x6D703EF3 + v333, 0xD);
		v347 = __ROL4__(v498 + (v345 ^ (v346 | ~v344)) + 0x6D703EF3 + v337, 0xD);
		v348 = ~v346;
		v349 = __ROL4__(v344, 0xA);
		v350 = v341 + v347;
		v351 = __ROL4__(v346, 0xA);
		v352 = v510 + (v349 ^ (v350 | v348)) + 0x6D703EF3 + v341;
		v353 = ~v350;
		v354 = v345 + __ROL4__(v352, 7);
		v355 = __ROL4__(v350, 0xA);
		v356 = __ROL4__(v345 + 0x6D703EF3 + v501 + (v351 ^ (v354 | v353)), 5);
		v475 = v349 + v356;
		v357 = __ROL4__(v354, 0xA);
		v358 = __ROL4__(v508 + ((v349 + v356) & v354 | v355 & ~(v349 + v356)) + v349 + 0x7A6D76E9, 0xF);
		v491 = v351 + v358;
		v359 = __ROL4__(v475, 0xA);
		v360 = __ROL4__(v506 + ((v351 + v358) & v475 | v357 & ~(v351 + v358)) + v351 + 0x7A6D76E9, 5);
		v476 = v355 + v360;
		v361 = __ROL4__(v491, 0xA);
		v362 = __ROL4__(v510 + ((v355 + v360) & v491 | v359 & ~(v355 + v360)) + v355 + 0x7A6D76E9, 8);
		v492 = v357 + v362;
		v363 = __ROL4__(v500 + ((v357 + v362) & v476 | v361 & ~(v357 + v362)) + v357 + 0x7A6D76E9, 0xB);
		v364 = __ROL4__(v476, 0xA);
		v450 = v359 + v363;
		v365 = __ROL4__(v492, 0xA);
		v366 = __ROL4__(v504 + (v492 & (v359 + v363) | v364 & ~(v359 + v363)) + v359 + 0x7A6D76E9, 0xE);
		v477 = v361 + v366;
		v367 = __ROL4__(v450, 0xA);
		v368 = __ROL4__(v502 + ((v361 + v366) & v450 | v365 & ~(v361 + v366)) + v361 + 0x7A6D76E9, 0xE);
		v493 = v364 + v368;
		v369 = __ROL4__(v477, 0xA);
		v370 = __ROL4__(v514 + ((v364 + v368) & v477 | v367 & ~(v364 + v368)) + v364 + 0x7A6D76E9, 6);
		v451 = v365 + v370;
		v371 = __ROL4__(v493, 0xA);
		v478 = v367 + __ROL4__(v498 + ((v365 + v370) & v493 | v369 & ~(v365 + v370)) + v365 + 0x7A6D76E9, 0xE);
		v372 = __ROL4__(v365 + v370, 0xA);
		v373 = v369 + __ROL4__(v509 + (v478 & v451 | v371 & ~v478) + v367 + 0x7A6D76E9, 6);
		v494 = v371 + __ROL4__(v512 + (v478 & v373 | v372 & ~v373) + v369 + 0x7A6D76E9, 9);
		v374 = __ROL4__(v478, 0xA);
		v375 = __ROL4__(v499 + (v494 & v373 | v374 & ~v494) + v371 + 0x7A6D76E9, 0xC);
		v452 = __ROL4__(v373, 0xA);
		v376 = v374 + __ROL4__(v501 + ((v372 + v375) & v494 | v452 & ~(v372 + v375)) + v372 + 0x7A6D76E9, 9);
		v495 = __ROL4__(v494, 0xA);
		v479 = __ROL4__(v372 + v375, 0xA);
		v377 = v376 & (v372 + v375) | v495 & ~v376;
		v378 = v376;
		v379 = __ROL4__(v376, 0xA);
		v380 = v452 + __ROL4__(v503 + v377 + v374 + 0x7A6D76E9, 0xC);
		v381 = v495 + __ROL4__(v507 + (v380 & v378 | v479 & ~v380) + v452 + 0x7A6D76E9, 5);
		v382 = v380 & v381;
		v383 = __ROL4__(v380, 0xA);
		v384 = v479 + __ROL4__(v511 + (v382 | v379 & ~v381) + v495 + 0x7A6D76E9, 0xF);
		v385 = v379 + __ROL4__(v505 + (v384 & v381 | v383 & ~v384) + v479 + 0x7A6D76E9, 8);
		v386 = __ROL4__(v381, 0xA);
		v387 = v384 ^ v386;
		v388 = __ROL4__(v384, 0xA);
		v389 = v379 + v512 + (v385 ^ v387);
		v390 = v385 ^ v388;
		v391 = v383 + __ROL4__(v389, 8);
		v392 = __ROL4__(v385, 0xA);
		v393 = v383 + v514 + (v391 ^ v390);
		v394 = v391 ^ v392;
		v395 = v386 + __ROL4__(v393, 5);
		v396 = __ROL4__(v391, 0xA);
		v397 = v388 + __ROL4__(v386 + v511 + (v395 ^ v394), 0xC);
		v398 = v395 ^ v396 ^ v397;
		v399 = __ROL4__(v395, 0xA);
		v400 = v388 + v510 + v398;
		v401 = v397;
		v402 = v392 + __ROL4__(v400, 9);
		v403 = __ROL4__(v397, 0xA);
		v404 = v392 + v500 + (v399 ^ v402 ^ v401);
		v405 = v402 ^ v403;
		v406 = v396 + __ROL4__(v404, 0xC);
		v407 = __ROL4__(v402, 0xA);
		v408 = v396 + v509 + (v406 ^ v405);
		v409 = v406 ^ v407;
		v410 = v399 + __ROL4__(v408, 5);
		v411 = __ROL4__(v406, 0xA);
		v412 = v399 + v508 + (v410 ^ v409);
		v413 = v410 ^ v411;
		v414 = v403 + __ROL4__(v412, 0xE);
		v415 = __ROL4__(v410, 0xA);
		v416 = v407 + __ROL4__(v403 + v507 + (v414 ^ v413), 6);
		v417 = v414 ^ v415 ^ v416;
		v418 = __ROL4__(v414, 0xA);
		v419 = v411 + __ROL4__(v407 + v506 + v417, 8);
		v420 = v415 + __ROL4__(v411 + v499 + (v418 ^ v419 ^ v416), 0xD);
		v453 = __ROL4__(v416, 0xA);
		v480 = __ROL4__(v419, 0xA);
		v421 = v415 + v501 + (v420 ^ v419 ^ v453);
		v422 = v420 ^ v480;
		v423 = v418 + __ROL4__(v421, 6);
		v424 = __ROL4__(v420, 0xA);
		v425 = v453 + __ROL4__(v418 + v505 + (v423 ^ v422), 5);
		v496 = __ROL4__(v423, 0xA);
		v426 = v480 + __ROL4__(v453 + v498 + (v425 ^ v423 ^ v424), 0xF);
		v427 = v496 ^ v426;
		v428 = v426;
		v429 = __ROL4__(v426, 0xA);
		v430 = v424 + __ROL4__(v480 + v504 + (v425 ^ v427), 0xD);
		v454 = __ROL4__(v425, 0xA);
		v431 = v430 ^ v429;
		v432 = v496 + __ROL4__(v424 + v503 + (v454 ^ v430 ^ v428), 0xB);
		v433 = v441 + a1[1] + __ROL4__(v430, 0xA);
		a1[1] = v429 + a1[2] + __ROL4__(v446, 0xA);
		a1[2] = v435 + v454 + a1[3];
		a1[3] = v462 + v454 + __ROL4__(v496 + v502 + (v432 ^ v431), 0xB) + a1[4];
		result = v462 + v432 + *a1 + __ROL4__(v501 + (v441 ^ (v446 | ~v435)) + v467 - 0x56AC02B2, 6);
		*a1 = v433;
		a1[4] = result;
		return result;
	}

	int sub_10002480(unsigned int* a1, unsigned char* a2)
	{
		unsigned int i; // esi
		unsigned int* v5; // edx
		unsigned char v6; // cl
		unsigned int v8[16]; // [esp+Ch] [ebp-44h] BYREF
		memset(v8, 0, sizeof(v8));
		for (i = 0; i < 0x18; ++i)
		{
			++a2;
			v5 = &v8[i >> 2];
			v6 = 8 * (i & 3);
			*v5 ^= (unsigned char)*(a2 - 1) << v6;
		}
		v8[0xE] = 0xC0;
		v8[6] ^= 0x80u;
		v8[0xF] = 0;
		return sub_10001130(a1, v8);
	}

	void SeedToKeyForDFCV_DGi13(const CBinary& ucSeed, CBinary& ucKey)
	//void SeedToKeyForDFCV_DGi13(unsigned char* ucSeed, unsigned char* ucKey)
	{
		unsigned char uSeed[4] = {0};
		uSeed[0] = ucSeed[0];
		uSeed[1] = ucSeed[1];
		uSeed[2] = ucSeed[2];
		uSeed[3] = ucSeed[3];
		int i; // edx
		unsigned int v6; // ecx
		unsigned char v7[16]; // [esp+0h] [ebp-5Ch]
		unsigned int v8[5]; // [esp+10h] [ebp-4Ch] BYREF
		unsigned char v9[24]; // [esp+24h] [ebp-38h] BYREF
		unsigned char ucOutPut[20]; // [esp+44h] [ebp-18h] BYREF
		*(unsigned int*)&v7[0] = 0x9D646989;
		*(unsigned int*)&v7[4] = 0x10CADCC9;
		*(unsigned int*)&v7[8] = 0x0A2BA295;
		*(unsigned int*)&v7[12] = 0xE4B8C36B;
		memset(v9, 0, sizeof(v9));
		memset(ucOutPut, 0, sizeof(ucOutPut));
		v8[0] = 0x67452301;
		v8[1] = 0xEFCDAB89;
		v8[2] = 0x98BADCFE;
		v8[3] = 0x10325476;
		v8[4] = 0xC3D2E1F0;
		memcpy(v9, v7, 16);
		*(unsigned int*)&v9[16] = *(unsigned int*)uSeed;
		sub_10002480(v8, v9);
		for (i = 0; i < 20; i += 4)
		{
			v6 = v8[i >> 2];
			ucOutPut[i] = v6 & 0xFF;
			ucOutPut[i + 1] = (v6 >> 8) & 0xFF;
			ucOutPut[i + 2] = (v6 >> 16) & 0xFF;
			ucOutPut[i + 3] = (v6 >> 24) & 0xFF;
		}
		//memcpy(ucKey, ucOutPut, 8);
		for (int k = 0; k < 8; k++)
			ucKey.Add(ucOutPut[k]);
	}

	//void SaftySeedForDFLZ_L2EV(unsigned char* ucInput, unsigned char* ucOutput)
	void SaftySeedForDFLZ_L2EV(const CBinary& ucInput, CBinary& ucOutput)
	{
		int uBase; // r12
		int v3; // lr
		int v4; // r3
		unsigned int uKey; // r0
		unsigned int v6; // r2
		int v7; // r5
		int v8; // r5

		uBase = 0x4C495551;
		v3 = 2;
		v4 = 0x56FAB551;
		uKey = ucInput[3] + (ucInput[2] << 8) + (ucInput[1] << 0x10) + (ucInput[0] << 0x18);;
		v6 = ~uKey;
		do
		{
			--v3;
			v7 = (((0x10 * v6) ^ (v6 >> 5)) + v6) ^ uBase;
			uBase += 0xAB16000;
			uKey += v7;
			v8 = (((0x10 * uKey) ^ (uKey >> 5)) + uKey) ^ v4;
			v4 += 0xAB16000;
			v6 += v8;
		} while (v3);
		//ucOutput[0] = (uKey >> 24) & 0xFF;
		//ucOutput[1] = (uKey >> 16) & 0xFF;
		//ucOutput[2] = (uKey >> 8) & 0xFF;
		//ucOutput[3] = uKey;
		ucOutput.Add((uKey >> 24) & 0xFF);
		ucOutput.Add((uKey >> 16) & 0xFF);
		ucOutput.Add((uKey >> 8) & 0xFF);
		ucOutput.Add(uKey);
	}
	//久隆转向机控制器
	//void  Seed2Key_JL_EHPS(unsigned char* ucSeed, unsigned char* ucKey)
	void  Seed2Key_JL_EHPS(const CBinary& ucInput, CBinary& ucOutput)
	{
		//int int_2 = (int)ucInput[0] * 16777216 + (int)ucInput[1] * 65536 + (int)ucInput[2] * 256 + (int)ucInput[3];
		int int_2 = ucInput[3] + (ucInput[2] << 8) + (ucInput[1] << 0x10) + (ucInput[0] << 0x18);;

		int int_3 = 87107551;
		int num = 0;
		if (int_2 != 0)
		{
			for (int i = 0; i < 35; i++)
			{
				if (((long)int_2 & 0x80000000) != 0)
				{
					int_2 <<= 1;
					int_2 ^= int_3;
				}
				else
				{
					int_2 <<= 1;
				}
			}
			num = int_2;
		}
		//ucKey[0] = (num >> 24) & 0xFF;
		//ucKey[1] = (num >> 16) & 0xFF;
		//ucKey[2] = (num >> 8) & 0xFF;
		//ucKey[3] = (num >> 0) & 0xFF;

		ucOutput.Add((num >> 24) & 0xFF);
		ucOutput.Add((num >> 16) & 0xFF);
		ucOutput.Add((num >> 8) & 0xFF);
		ucOutput.Add((num >> 0) & 0xFF);
	}


	void  SaftySeedForDFCV_INS_III(const CBinary& ucInput, CBinary& ucOutput)
	{
		ucOutput = CBinary(16);
		UINT num = ucInput[3];
		num |= (ucInput[2] << 8);
		num |= (ucInput[1] << 16);
		num |= (ucInput[0] << 24);
		std::vector<UINT> array2 = { 386033776U ,1736868967U,1482709603U,1482183425U };
		std::vector<UINT> array3 = { num,15794176U,16843010U,50595078U };

		int num5 = 0;
		int num6 = 2654435769U;
		for (int i = 0; i < 32; ++i)
		{
			num5 += num6;
			array3[0] += ((array3[1] << 4) + array2[0] ^ array3[1] + num5 ^ (array3[1] >> 5) + array2[1]);
			array3[1] += ((array3[0] << 4) + array2[2] ^ array3[0] + num5 ^ (array3[0] >> 5) + array2[3]);
			array3[2] += ((array3[3] << 4) + array2[0] ^ array3[3] + num5 ^ (array3[3] >> 5) + array2[1]);
			array3[3] += ((array3[2] << 4) + array2[2] ^ array3[2] + num5 ^ (array3[2] >> 5) + array2[3]);
		}
		ucOutput[15] = (BYTE)(array3[3] & 255U);
		ucOutput[14] = (BYTE)(array3[3] >> 8 & 255U);
		ucOutput[13] = (BYTE)(array3[3] >> 16 & 255U);
		ucOutput[12] = (BYTE)(array3[3] >> 24 & 255U);
		ucOutput[11] = (BYTE)(array3[2] & 255U);
		ucOutput[10] = (BYTE)(array3[2] >> 8 & 255U);
		ucOutput[9] = (BYTE)(array3[2] >> 16 & 255U);
		ucOutput[8] = (BYTE)(array3[2] >> 24 & 255U);
		ucOutput[7] = (BYTE)(array3[1] & 255U);
		ucOutput[6] = (BYTE)(array3[1] >> 8 & 255U);
		ucOutput[5] = (BYTE)(array3[1] >> 16 & 255U);
		ucOutput[4] = (BYTE)(array3[1] >> 24 & 255U);
		ucOutput[3] = (BYTE)(array3[0] & 255U);
		ucOutput[2] = (BYTE)(array3[0] >> 8 & 255U);
		ucOutput[1] = (BYTE)(array3[0] >> 16 & 255U);
		ucOutput[0] = (BYTE)(array3[0] >> 24 & 255U);
	}

	//void SaftySeedForDFCV_AMT3(unsigned char* byte_0, unsigned char* byte_2)
	void  SaftySeedForDFCV_AMT3(const CBinary& ucInput, CBinary& ucOutput)
	{
		unsigned int array1[4] = { 0 };
		unsigned int array2[4] = { 0 };
		unsigned int array3[4] = { 0,15794176, 16843010, 50595078 };

		for (int i = 0; i < 4; i++)
		{
			array1[i] = (unsigned int)ucInput[i];
		}
		unsigned int num1 = array1[3];
		num1 |= array1[2] << 8;
		num1 |= array1[1] << 16;
		num1 |= array1[0] << 24;

		array3[0] = num1;
		array2[0] = 620849264U;
		array2[1] = 1736868967U;
		array2[2] = 381660452U;
		array2[3] = 2293943553U;
		{
			unsigned int num = array3[0];
			unsigned int num2 = array3[1];
			unsigned int num3 = array3[2];
			unsigned int num4 = array3[3];
			unsigned int num5 = 0U;
			unsigned int num6 = 2654435769U;
			unsigned int num7 = array2[0];
			unsigned int num8 = array2[1];
			unsigned int num9 = array2[2];
			unsigned int num10 = array2[3];
			for (unsigned int num11 = 0U; num11 < 32U; num11 += 1U)
			{
				num5 += num6;
				num += ((num2 << 4) + num7) ^ (num2 + num5) ^ ((num2 >> 5) + num8);
				num2 += ((num << 4) + num9) ^ (num + num5) ^ ((num >> 5) + num10);
				num3 += ((num4 << 4) + num7) ^ (num4 + num5) ^ ((num4 >> 5) + num8);
				num4 += ((num3 << 4) + num9) ^ (num3 + num5) ^ ((num3 >> 5) + num10);
			}
			array3[0] = num;
			array3[1] = num2;
			array3[2] = num3;
			array3[3] = num4;
		}
		//byte_2[15] = (unsigned char)(array3[3] & 255U);
		//byte_2[14] = (unsigned char)((array3[3] >> 8) & 255U);
		//byte_2[13] = (unsigned char)((array3[3] >> 16) & 255U);
		//byte_2[12] = (unsigned char)((array3[3] >> 24) & 255U);
		//byte_2[11] = (unsigned char)(array3[2] & 255U);
		//byte_2[10] = (unsigned char)((array3[2] >> 8) & 255U);
		//byte_2[9] = (unsigned char)((array3[2] >> 16) & 255U);
		//byte_2[8] = (unsigned char)((array3[2] >> 24) & 255U);
		//byte_2[7] = (unsigned char)(array3[1] & 255U);
		//byte_2[6] = (unsigned char)((array3[1] >> 8) & 255U);
		//byte_2[5] = (unsigned char)((array3[1] >> 16) & 255U);
		//byte_2[4] = (unsigned char)((array3[1] >> 24) & 255U);
		//byte_2[3] = (unsigned char)(array3[0] & 255U);
		//byte_2[2] = (unsigned char)((array3[0] >> 8) & 255U);
		//byte_2[1] = (unsigned char)((array3[0] >> 16) & 255U);
		//byte_2[0] = (unsigned char)((array3[0] >> 24) & 255U);

		ucOutput.Add((array3[0] >> 24) & 0xFF);
		ucOutput.Add((array3[0] >> 16) & 0xFF);
		ucOutput.Add((array3[0] >> 8) & 0xFF);
		ucOutput.Add(array3[0] & 0xFF);
		ucOutput.Add((array3[1] >> 24) & 0xFF);
		ucOutput.Add((array3[1] >> 16) & 0xFF);
		ucOutput.Add((array3[1] >> 8) & 0xFF);
		ucOutput.Add(array3[1] & 0xFF);
		ucOutput.Add((array3[2] >> 24) & 0xFF);
		ucOutput.Add((array3[2] >> 16) & 0xFF);
		ucOutput.Add((array3[2] >> 8) & 0xFF);
		ucOutput.Add(array3[2] & 0xFF);
		ucOutput.Add((array3[3] >> 24) & 0xFF);
		ucOutput.Add((array3[3] >> 16) & 0xFF);
		ucOutput.Add((array3[3] >> 8) & 0xFF);
		ucOutput.Add(array3[3] & 0xFF);
	}

}
