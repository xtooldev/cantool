#include "StdAfx.h"
#include "HD_SANYI.h"
#include "define.h"
#include "LK_TCU.h"
#include "../../../MODULE/HD_XTBASE/IntelligenceParamManage.h"
#include "AutoScan.h"
#include "base64encode.h"
#include "sanyi_J1939.h"
#include "sanyi_module_base.h"
#include "sanyi_dtc_info.h"

using namespace HD_SANYI;

//IVCI+ 项目变更（2020.7.24）(idm  --  中间两个字节没有用，这里第二个字节做引脚，第三个字节的第1位表示是否支持120欧电阻)  by lgd at 2020.7.24

using namespace HD_SANYI;

using namespace nsp_sanyi_dtc_info;

//IVCI+ 项目变更（2020.7.24）(idm  --  中间两个字节没有用，这里第二个字节做引脚，第三个字节的第1位表示是否支持120欧电阻)  by lgd at 2020.7.24
using namespace nsp_sanyi_module_base;

UINT iStartIdmOld_FAW = 0;
#define OLDSYSUPDATE_IVCIPLUS




BYTE m_FTEcuID;

BOOL bIsAutoScan_SANYI = FALSE;
BOOL g_IsCurrtenProject_SANYI = FALSE;//是否是本工程，FALSE为动态调用
DWORD g_nFunMask_SANYI = 0;//功能掩码，主要用于诊断报告生成（按位取功能），0x01:读码且无码；0x02:有故障码；0x04:版本信息，0x08：数据流；0x10:冻结帧;0x20:清码
void VehicleData_SANYI_SetNoTroubleCode(DWORD uTaskId)
{
	dbglog("WSP:VehicleData_SetNoTroubleCode_SANYI  uTaskId = %08X\n", uTaskId);
	if (g_IsCurrtenProject_SANYI)
		VehicleData.SetNoTroubleCode(uTaskId);
	g_nFunMask_SANYI |= 0x01;
}
void VehicleData_SANYI_WriteTroubleCode(DWORD uTaskId)
{
	dbglog("WSP:VehicleData_WriteTroubleCode_SANYI  uTaskId = %08X\n", uTaskId);

	if (g_IsCurrtenProject_SANYI)
		VehicleData.WriteTroubleCode(uTaskId);
	g_nFunMask_SANYI |= 0x02;
}
void VehicleData_SANYI_WriteEcuInfo(DWORD uTaskId)
{
	dbglog("WSP:VehicleData_WriteEcuInfo_SANYI  uTaskId = %08X\n", uTaskId);
	if (g_IsCurrtenProject_SANYI)
		VehicleData.WriteEcuInfo(uTaskId);
	g_nFunMask_SANYI |= 0x04;
}
void VehicleData_SANYI_WriteDatastream(DWORD uTaskId)
{
	dbglog("WSP:VehicleData_WriteDatastream_SANYI  uTaskId = %08X\n", uTaskId);
	if (g_IsCurrtenProject_SANYI)
		VehicleData.WriteDatastream(uTaskId);
	g_nFunMask_SANYI |= 0x08;
}

void VehicleData_SANYI_WriteTroubleCode(DWORD uTaskId, CGroup<struct tagFaultCode>& vctTagDtc)
{
	dbglog("WSP:VehicleData_WriteTroubleCode_SANYI1  uTaskId = %08X\n", uTaskId);
	dbglog("WSP:VehicleData_WriteTroubleCode_SANYI1  dtcNum = %d\n", vctTagDtc.GetSize());
	VehicleData.WriteTroubleCode(uTaskId, vctTagDtc);
}
void VehicleData_SANYI_SetDiagPath(TString strPath)
{
	dbglog("WSP:VehicleData_SetDiagPath_SANYI  strPath = %s\n", strPath.AsString());
	VehicleData.SetDiagPath(strPath);
}
void VehicleData_SANYI_Init()
{
	dbgstring("WSP:VehicleData_Init_SANYI\n");
	VehicleData.Init();
}
void VehicleData_SANYI_SetModuleName(DWORD uTaskId, TString strName)
{
	dbglog("WSP:VehicleData_SetModuleName_SANYI  uTaskId = %08X\n", uTaskId);
	dbglog("WSP:VehicleData_SetModuleName_SANYI  strName = %s\n", strName.AsString());
	VehicleData.SetModuleName(uTaskId, strName);
}
void VehicleData_SANYI_SetVehicleName(TString strName)
{
	dbglog("WSP:VehicleData_SetVehicleName_SANYI  strName = %s\n", strName.AsString());
	VehicleData.SetVehicleName(strName);
}
void VehicleData_SANYI_Save()
{
	dbglog("WSP:VehicleData.Save()\n");
	VehicleData.Save();
}
TString VehicleData_SANYI_GetFullSystemName()
{
	return VehicleData.GetFullSystemName();
}
void VehicleData_SANYI_ShowReportV2()
{
	dbglog("WSP:VehicleData_ShowReportV2_SANYI  strShowModel = %d\n", VehicleData.REPORT_V2_TYPE_NORMAL_SCAN);
	VehicleData.ShowReportV2(VehicleData.REPORT_V2_TYPE_NORMAL_SCAN);
}

static BOOL IVCIPlus(CDiagnoseSystem* pSystem, UINT idm)
{
	BOOL bRet = FALSE;
	BYTE nSendLine = 0;
	BYTE nRecvLine = 0;

	/***用于车型扫描2/6***END***/
	/*** VCI+项目 1/3  ***START*** add by hwx 2020/4/10 ***/
	//是否是IVCI+

	BOOL bIsLinux = FALSE;
	if (CDisplay::GetAppName() == "F510" || CDisplay::GetAppName() == "F520")
	{
		bIsLinux = TRUE;
	}
	if (!IsSupportSelectPin() || bIsLinux)
	{
// 		不是IVCI+
// 				TString strFile;
// 				//add for IVCI+ by hwx 2020.7.17
// 				TString fvalue = CDisplay::GetAppName();
// 				//是否是H6D系列
// 				if (fvalue == TString("H6DPRO"))
// 				{
// 					//是H6D系列
// 					strFile = CConfig::GetDispDirectory() + "DTC_HELP\\" + "HD_IVCI_PLUS\\" + "IVCI_PLUS.jpg";
// 					if (CDataFile::IsExistFile(strFile))
// 					{
// 						ShowPicture(strFile, "", 0, "");
// 					}
// 					else
// 					{
// 						MessageBox(TEXT_IVCI_INFO);
// 					}
// 					//CConfig::EnableMessage(FALSE);
// 				}
// 				else
// 				{
// 					if (CConfig::IsShowMessage()) CDisplay::MessageBox(TEXT_CHECK_FAIL);
// 				}
		CDisplay::MessageBox(TEXT_CHECK_FAIL);
		return FALSE;
	}

	//是IVCI+的下位机
	if (MessageBox(TEXT_IVCI_INFO1, MB_OKCANCEL) == IDCANCEL)//IVCI_INFO1 进入系统失败，请尝试使用智能OBD跳线
	{
		//CConfig::EnableMessage(FALSE);
		return bRet;
	}
	UINT idm_old = idm;
	while (1)
	{
		/*** VCI+项目 1/3 ***END***/
		//add for VCI+  by WangRong 2020-02-27
		BYTE nSendLine = 0;
		BYTE nRecvLine = 0;
		/*** VCI+项目 2/3  ***START*** add by hwx 2020/4/10 ***/
		BYTE nCan120R = 0;
		BYTE nbps=0;
		bRet = SelectCanPin(nSendLine, nRecvLine, nCan120R,nbps);

		/*** VCI+项目 2/3 ***END***/
		if (bRet == 0)//点击返回
		{
			return bRet;
		}

		idm = (idm & 0xFF0000FF);//把中间两位置为0

		idm = (idm | 0x800000);//表示是否支持IVCI+
		idm = (idm | (nCan120R << 16));
		idm = (idm | (nbps+8) << 20);
		idm = (idm | (nSendLine << 12));
		idm = (idm | (nRecvLine << 8));

		bRet = pSystem->EnterSystem(idm);
		if (bRet == TRUE)
		{
			//如果成功进入系统
			//CConfig::EnableMessage(FALSE);
			break;
		}
		else
		{
			if (MessageBox(TEXT_IVCI_INFO2, MB_YESNO) == IDNO)//进入系统失败，是否继续请尝试使用智能OBD跳线
			{
				//CConfig::EnableMessage(FALSE);
				break;
			}
		}
	}

	idm = idm_old;//还原

	return bRet;
}

static BOOL IVCIPlusNew(UINT idm)
{
	BOOL bRet = FALSE;
	BYTE nSendLine = 0;
	BYTE nRecvLine = 0;

	/***用于车型扫描2/6***END***/
	/*** VCI+项目 1/3  ***START*** add by hwx 2020/4/10 ***/
	//是否是IVCI+

	BOOL bIsLinux = FALSE;
	if (CDisplay::GetAppName() == "F510" || CDisplay::GetAppName() == "F520")
	{
		bIsLinux = TRUE;
	}
	if (!IsSupportSelectPin() || bIsLinux)
	{
		//CDisplay::MessageBox(TEXT_CHECK_FAIL);
		return FALSE;
	}
	//是IVCI+的下位机
	if (MessageBox(TEXT_IVCI_INFO1, MB_OKCANCEL) == IDCANCEL)//IVCI_INFO1 进入系统失败，请尝试使用智能OBD跳线
	{
		//CConfig::EnableMessage(FALSE);
		return bRet;
	}
	UINT idm_old = idm;
	while (1)
	{
		/*** VCI+项目 1/3 ***END***/
		//add for VCI+  by WangRong 2020-02-27
		BYTE nSendLine = 0;
		BYTE nRecvLine = 0;
		/*** VCI+项目 2/3  ***START*** add by hwx 2020/4/10 ***/
		BYTE nCan120R = 0;
		bRet = SelectCanPin(nSendLine, nRecvLine, nCan120R);
		/*** VCI+项目 2/3 ***END***/
		if (bRet == 0)//点击返回
		{
			return bRet;
		}
		idm = (idm & 0xF000FF);//把中间两位置为0
		idm = (idm | 0x800000);//表示是否支持IVCI+
		idm = (idm | (nCan120R << 16));
		idm = (idm | (nSendLine << 12));
		idm = (idm | (nRecvLine << 8));

		//bRet = afxGetdfcvModuleBase()->EnterSystem(idm);
		if (bRet == TRUE)
		{
			//如果成功进入系统
			//CConfig::EnableMessage(FALSE);
			break;
		}
		else
		{
			if (MessageBox(TEXT_IVCI_INFO2, MB_YESNO) == IDNO)//进入系统失败，是否继续请尝试使用智能OBD跳线
			{
				//CConfig::EnableMessage(FALSE);
				break;
			}
		}
	}
	idm = idm_old;//还原
	return bRet;
}

BOOL OldSanyiScan(UINT idm)
{
#ifdef _COCOS
	VehicleData.Init();
#endif

	//为自动扫描添加的代码
	if (strlen(CConfig::GetDynamicInfo().AsString()))
	{
		SysDtcMsg* AS = nullptr;
		if (ParseInfoFromDynamic(AS))
		{
			if (AS->type == QTF_AUTOSCAN || AS->type == QTF_CLEARDTC)
			{
				QTF_ERROR ret = QTF_ERR_OK;
				CConfig::SetSpecFlag(ESF_AUTO_SCAN);//设置自动扫描无任何界面弹框形式
				ret = SanyiScan(AS->pDtc, AS->pSys, AS->type, AS->iReadDtcFlag, AS->DTC, SecondCheckSystem);
				CConfig::SetSpecFlag(ESF_NORMAL);//还原原始弹框模式
				return ret;
			}
			return FALSE;
		}
		else
		{
			//return FALSE;
			CConfig::SetDynamicInfo("");//防止出现菜单点不动
		}
	}
	BOOL bRet = FALSE;
	//HD_XTBASE::IntelligentData m_IntelligentData;
	TString strTemp = CConfig::GetDynamicInfo();
	//BOOL bRet = HD_XTBASE::StrToIntelligentData(m_IntelligentData, strTemp);
	//IntelligenceParamManage::GetInstance().init(m_IntelligentData);

	CDiagnoseSystem *pSystem = NULL;
	CDatabase::SetDatabase(CConfig::GetLanguage() + "_HD_SANYI.db");
	if (IDEXIT == CDisplay::StatusBox(TEXT_CHECKING)) return FALSE;

	//添加最近诊断系统 -- by lgd at 2020.5.23
	BYTE bType = CConfig::GetScanType();//获取诊断类型
	if (bType == 3)
	{
		//如果是最近诊断在进入系统时，把标题设置成最近诊断
		CConfig::SetTitle(LoadText(TEXT_ENTER_LAST_DIAG));
	}
	//添加最近诊断系统 -- by lgd at 2020.5.23

	BOOL bIVCIPlus = FALSE;
	switch (idm & 0x00FFFFFF) {
	case 0x01://绿控TCU
	case 0x02://绿控整车控制器VCU
		pSystem = new CLK_TCU();
		bIVCIPlus = TRUE;
		break;
	default:
		return TRUE;
		break;
	}
	ASSERT(pSystem != NULL);
	/***用于车型扫描3/6  初始化变量***START***add by dj 2020/3/17***/
	//在原来的_ModuleScan()中的添加以下代码
	pSystem->m_qtfScanType = QTF_DIAGNOSE;
	UINT idm_old = idm;
	/***用于车型扫描3/6***END***/
	//add for IVCI+ by hwx 2020.7.17
	BOOL bShowMessage = CConfig::IsShowMessage();
	BOOL aRet = pSystem->EnterSystem(idm);
	if (aRet) {
		SetMaterialIdm("PD_SANYI", idm);
		if (!pSystem->Diagnose(idm))
			MessageBox(TEXT_COMM_FAIL, MB_OK);
		pSystem->ExitSystem(idm);
		idm = 0;
		debug("123456");
		SetMaterialIdm("PD_SANYI", idm);
	}
	else {
		//add for IVCI+ by hwx 2020.7.17
		/***用于车型扫描2/6  如果是自动扫描不进入该功能***START***add by dj 2020/3/17***/
		if (bIVCIPlus && pSystem->m_qtfScanType == QTF_DIAGNOSE)//是否需要ivci+ 提示
		{
			BOOL bRet = IVCIPlus(pSystem, idm);
			if (bRet == FALSE)
			{
				delete pSystem;
				return FALSE;
				//if (CConfig::IsShowMessage()) CDisplay::MessageBox(TEXT_CHECK_FAIL);
			}
			SetMaterialIdm("PD_SANYI", idm);
			if (!pSystem->Diagnose(idm))
				CDisplay::MessageBox(TEXT_COMM_FAIL, MB_OK);
			pSystem->ExitSystem(idm);
			idm = 0;
			debug("123456");
			SetMaterialIdm("PD_SANYI", idm);
		}
		else
		{
			if (CConfig::IsShowMessage()) CDisplay::MessageBox(TEXT_CHECK_FAIL);
			//CConfig::EnableMessage(bShowMessage);
		}
		delete pSystem;
		return FALSE;
	}
	delete pSystem;
	bType = CConfig::GetScanType();
	if (bType != 3)
	{
		SaveRecentDiag(idm_old, CDisplay::GetMenuPath());
	}
	if (aRet)
	{
#ifdef _COCOS
		VehicleData.Show();
#endif
	}
	return TRUE;
	return 0;
}

BOOL CreateOldSysObject(CDiagnoseSystem*& pSystem, UINT idm, int nFromNormal = 0)
{
	//nFromNormal : 0 => 正常进系统， 1 => 车型扫描
	BOOL ret = FALSE;
	switch (idm & 0xFFFF)
	{
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x08:
	case 0x09:
	case 0x0a:
	case 0x0b:
	case 0x0c:
	case 0x0d:
	case 0x0e:
	case 0x0f:
	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
	case 0x18:
	case 0x19:
	case 0x1A:
		pSystem = new SANYI_J1939();
		ret = true;
		break;
	}
	return ret;
}
BOOL SanyiJ1939Scan(UINT idm)
{
	CDiagnoseSystem* pSystem = NULL;
	CDatabase::SetDatabase(CConfig::GetLanguage() + "_SANYI.DB");
	CDisplay::StatusBox(TEXT_CHECKING);

	//添加最近诊断系统 -- by lgd at 2020.5.23
	BYTE bType = CConfig::GetScanType();//获取诊断类型
	if (bType == 3)
	{
		//如果是最近诊断在进入系统时，把标题设置成最近诊断
		CConfig::SetTitle(LoadText(TEXT_ENTER_LAST_DIAG));
	}
	//添加最近诊断系统 -- by lgd at 2020.5.23

	BOOL bIVCIPlus = TRUE;

	if (CreateOldSysObject(pSystem, idm) == FALSE)
	{
		return FALSE;
	}
	ASSERT(pSystem != NULL);
	/***用于车型扫描3/6  初始化变量***START***add by dj 2020/3/17***/
	//在原来的_ModuleScan()中的添加以下代码
	pSystem->m_qtfScanType = QTF_DIAGNOSE;
	/***用于车型扫描3/6***END***/
		//add for IVCI+ by hwx 2020.7.17
	BOOL bShowMessage = CConfig::IsShowMessage();
	BOOL aRet = pSystem->EnterSystem(idm);
	if (aRet)
	{
		VehicleData.SetModuleName(idm, CConfig::GetTitle());
		if (!pSystem->Diagnose(idm))
			MessageBox(TEXT_COMM_FAIL, MB_OK);
		pSystem->ExitSystem(idm);
	}
	else
	{
		//add for IVCI+ by hwx 2020.7.17
		if (bIVCIPlus == TRUE)//是否需要ivci+ 提示
		{
			BOOL bRet = IVCIPlus(pSystem, idm);
			if (bRet == FALSE)
			{
				return FALSE;
				//if (CConfig::IsShowMessage()) CDisplay::MessageBox(TEXT_CHECK_FAIL);
			}
			VehicleData.SetModuleName(idm, CConfig::GetTitle());
			if (!pSystem->Diagnose(idm))
				MessageBox(TEXT_COMM_FAIL, MB_OK);

			pSystem->ExitSystem(idm);
		}
		else
		{
			if (CConfig::IsShowMessage()) CDisplay::MessageBox(TEXT_CHECK_FAIL);
			//CConfig::EnableMessage(bShowMessage);
		}
		delete pSystem;
		return FALSE;
	}
	delete pSystem;
	bType = CConfig::GetScanType();
	if (bType != 3)
	{
		SaveRecentDiag(idm, CDisplay::GetMenuPath());
	}
	if (aRet)
	{
#ifdef _COCOS
		VehicleData.SetDiagPath(CDisplay::GetMenuPath());
#endif
	}
	return TRUE;
}

BOOL SanyiNewModule(UINT idm)
{
	UINT idm_old = idm;
	BYTE bType = CConfig::GetScanType();//获取诊断类型
	if (bType == 3)
	{
		//如果是最近诊断在进入系统时，把标题设置成最近诊断
		CConfig::SetTitle(LoadText(TEXT_ENTER_LAST_DIAG));
	}
	//添加最近诊断系统

	BOOL bRet = afxGetNYJXModuleBase()->EnterSystem(idm);
	if (!bRet)
	{
		bRet = IVCIPlusNew(idm);//智能跳线
		if (!bRet)
		{
			//MessageBox(TEXT_DIAG_FAIL_NOTICE);
			return bRet;
		}
	}
	SetMaterialIdm("PD_SANYI", idm);
	afxGetNYJXModuleBase()->Diagnose(idm);
	afxGetNYJXModuleBase()->ExitSystem(idm);
	idm = 0;
	debug("123456");
	SetMaterialIdm("PD_SANYI", idm);
	afxDelNYJXModeuleBase();

	//添加最近诊断系统 
	bType = CConfig::GetScanType();
	if (bType != 3)
	{
		SaveRecentDiag(idm_old, CDisplay::GetMenuPath());
	}
	return bRet;
}
BOOL NewSanyiScan(UINT idm)
{
	bool bRet = FALSE;
	if (0x20 == ((idm >> 16) & 0xff))
	{
		bRet = SanyiNewModule(idm);
	}
	else
	{
		switch (idm & 0x00FFFFFF)
		{
		case 0x03:
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
		case 0x08:
		case 0x09:
		case 0x0a:
		case 0x0b:
		case 0x0c:
		case 0x0d:
		case 0x0e:
		case 0x0f:
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x15:
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1A:
			bRet = SanyiJ1939Scan(idm);
			break;
		}
	}
	return bRet;
}

BOOL SanyiScan(UINT idm)
{
	bool bRet = FALSE;
	if (0x20 == ((idm >> 16) & 0xff))
	{
		// bRet = NewDfcvScan(idm);
	}
	else
	{
		bRet = OldSanyiScan(idm);
	}

	return bRet;
}


/***用于车型扫描4/6  实现DfcvScan的重载***START***add by dj 2020/3/17***/
QTF_ERROR SanyiScan(CScanDtc* pDtc, CScanSys* pSys, QTF_TYPE type, UINT& iReadDtcFlag, CGroup<struct tagTroubleCode>& DTC, QTF_ERROR(*fnSecondCheckSystem)(CScanSys*, QTF_TYPE, BOOL))
{//自动扫描使用
#ifdef _COCOS
	VehicleData.Init();
#endif
	UINT idm = pSys->GetTaskId();
	QTF_ERROR ret = QTF_ERR_OK;

	CDiagnoseSystem *pSystem=NULL;
	CDatabase::SetDatabase(CConfig::GetLanguage()+"_HD_SANYI.db");
	if (IDEXIT == CDisplay::StatusBox(TEXT_CHECKING)) return ret;
	switch (idm & 0x00FFFFFF)
	{
	case 0x01:
	case 0x02:
		pSystem = new CLK_TCU();
		break;
	//此处填写DfcvScan函数中swich语句default前的内容
	default:
#ifdef WIN32
		MessageBox("Not Found Code");
#endif
		return QTF_ERR_ENTER;
	}

	pSystem->m_qtfScanType = type;

	BOOL bEnterFlag = pSystem->EnterSystem(idm);
	if (bEnterFlag)
	{
		//3.系统筛选
		ret = fnSecondCheckSystem(pSys, type, TRUE);
		CDatabase::SetDatabase(CConfig::GetLanguage() + "_HD_SANYI.DB");
		if (ret == QTF_ERR_OK)
		{	//4.清码、读码
			pSystem->m_qftScanDtcFlag = QTF_READDTC_NA;
			pSystem->Diagnose(type);
			iReadDtcFlag = pSystem->m_qftScanDtcFlag;
			//DTC = pSystem->m_vsScanTroubleCode;
			for (unsigned int nDtc = 0; nDtc < pSystem->m_vsScanTroubleCode.GetSize(); nDtc++)
			{
				pDtc->Add(pSystem->m_vsScanTroubleCode[0].strCode, pSystem->m_vsScanTroubleCode[0].strText, pSystem->m_vsScanTroubleCode[0].strStat);
			}
		}

		//退出系统
		BOOL bExitFlag = pSystem->ExitSystem(0);
	}
	else
	{
		ret = QTF_ERR_ENTER;
	}

	if (pSystem == NULL)
	{
		return QTF_ERR_ENTER;
	}
	if (bEnterFlag)
	{
#ifdef _COCOS
		VehicleData.Show();
#endif
	}
	//添加最近诊断系统 -- by lgd at 2020.5.22
	//自动扫描中，获取最近诊断路径，从上面获取，不走此处代码
	//BYTE bType = CConfig::GetScanType();
 //	if (bType != 3)
 //	{
 //		//TString strTemp1 = CDisplay::GetMenuPath();
 //		SaveRecentDiag(idm);
 //	}
	//添加最近诊断系统 -- by lgd at 2020.5.22
	delete pSystem;
	return ret;
}
/***用于车型扫描4/6***END***/
