#ifndef _HD_SANYI_H_
#define _HD_SANYI_H_

#include "Diag.h"
#include "VMProtectSDK.h"
#include "../../../MODULE/HD_XTBASE/IntelligenceParamManage.h"

//idm 支持

#include "NewDSUI.h"

struct SysDtcMsg
{
	CScanDtc* pDtc;
	CScanSys* pSys;
	QTF_TYPE type;
	UINT iReadDtcFlag;
	CGroup<struct tagTroubleCode>DTC;
	INT flag;
};
extern BOOL bIsAutoScan_SANYI;
extern BOOL g_IsCurrtenProject_SANYI;
extern DWORD g_nFunMask_SANYI;
TString VehicleData_SANYI_GetFullSystemName();
void VehicleData_SANYI_WriteTroubleCode(DWORD uTaskId, CGroup<struct tagFaultCode>& vctTagDtc);
void VehicleData_SANYI_WriteTroubleCode(DWORD uTaskId);
void VehicleData_SANYI_SetDiagPath(TString strPath);
void VehicleData_SANYI_Init();
void VehicleData_SANYI_SetModuleName(DWORD uTaskId, TString strName);
void VehicleData_SANYI_SetNoTroubleCode(DWORD uTaskId);
void VehicleData_SANYI_WriteEcuInfo(DWORD uTaskId);
void VehicleData_SANYI_WriteDatastream(DWORD uTaskId);
void VehicleData_SANYI_SetVehicleName(TString strName);
void VehicleData_SANYI_Save();
void VehicleData_SANYI_ShowReportV2();

BOOL OldSanyiScan(UINT idm);
BOOL NewSanyiScan(UINT idm);


BOOL SanyiNewModule(UINT idm);

BOOL SanyiJ1939Scan(UINT idm);

/***用于车型扫描1/6  申明全局变量***START***Module_(去除hd_)***_Module(来源与重载scan函数)***add by dj 2020/3/17***/

BOOL SanyiScan(UINT idm);

QTF_ERROR SanyiScan(CScanDtc* pDtc, CScanSys* pSys, QTF_TYPE type, UINT& iReadDtcFlag, CGroup<struct tagTroubleCode>& DTC, QTF_ERROR(*fnSecondCheckSystem)(CScanSys*, QTF_TYPE, BOOL));
/***用于车型扫描1/6  申明全局变量***END***/
#endif
