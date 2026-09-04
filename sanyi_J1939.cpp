#include "SANYI_J1939.h"
#include "define.h"
#include "../HD_UTILS/code/Algo_manucalc.h"
#include "../HD_UTILS/code/xtool_public.h"
#include "file.h"
#include "../HD_UTILS/code/CommAdapter.h"


SANYI_J1939::SANYI_J1939()
{

}

BOOL SANYI_J1939::ConnectSystem(UINT idm)
{
	m_Idm = idm;
	CurrNetcfg.nProtocol = PT_CAN | CAN_EXT;
	CurrNetcfg.nToolId = 0x80808080;
	CurrNetcfg.vecPin = { "6E" };
	CurrNetcfg.vecBps = { "500K" };
	CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	CurrNetcfg.groupCommTime = { 0, 0, 1000, 80 };
	if (idm == 0x87000003)
	{
		CurrNetcfg.vecFilterId = { 0x18FF7708,0x18FF7A1A,0x18FECA64,0x18FF7313,0x18FF7414,0x18FECA63,0x18FF7111,0x18FF7212,0x18FECA62,0x18FF7B1B,0x18FECA65,
			0x16FF31C1,0x16FF32C2,0x18FF33C3,0x18FECAF0,0x16FF34C4,0x16FF35C5,0x18FF36C6,0x18FECAF1,0x18FF05A5,0x180464EB,0x180564EB,0x16FF41D1,0x16FF44D4,
			0x18FF03A3,0x18FFF101,0x16FF02A2,0x16FF03A2, 0x18FF25B5, 0x18FF26B6, 0x0CFF0123 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x87000004)
	{
		CurrNetcfg.vecFilterId = { 0x18FF01D0,0x18FF02D0,0x18FF03D0,0x18FF04D0,0x18FF05D0,0x18FF06D0,0x18FEF1D0,0x1CFF2ED0,0x18FF07D0,0x18FF08D0,0x18FF09D0,
			0x1CFF2AD0,0x1802F3D0,0x18E1F3D0,0x0CF00400,0x18FEF100 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x87000005)
	{
		CurrNetcfg.vecFilterId = { 0x0CFF40D7,0x0CFF41D7,0x0CFF42D7,0x0CFF43D7 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x87000006)
	{
		CurrNetcfg.vecFilterId = { 0x18FF50D2,0x18FF51D2,0x18FF70D4,0x18FF71D4,0x18FF60D3,0x18FF61D3,0x18FF90D6,0x180464EB,0x18FF05D0,0x18FF91D6,0x18FF52D2,0x18FF72D4,0x18FF62D3,0x18FF02D0,0x18FEBF0B,0x18FF03D0,0x18FF04D0 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x87000007)
	{
		CurrNetcfg.vecPin = { "19" };
		CurrNetcfg.vecBps = { "250K" };
		CurrNetcfg.vecFilterId = { 0x18F0010B,0x18FEBF0B,0x18FEAD0B,0x18FDC40B,0x0C00000B,0x0C00100B,0x0C000F0B,0x0C00290B,0x18FE4F0B,0x18F0090B };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x87000008)
	{
		CurrNetcfg.vecFilterId = { 0x18E5D0F3,0x18E6D0F3,0x18C2D0F3,0x18C1D0F3,0x1880D0F3,0x1881D0F3,0x1882D0F3,0x1883D0F3,0x1884D0F3,0x1885D0F3,0x1886D0F3,0x18F1D0F3,0x18F2D0F3,0x18F3D0F3,0x1801D0F3,0x18E1D0F3,0x18E2D0F3,0x18E3D0F3,0x18E4D0F3,0x18FF45F4 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x87000009)
	{
		CurrNetcfg.vecFilterId = { 0x18FFB003,0x18FFB103,0x18FFB203,0x18FFB303,0x18F00503 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x8700000A)
	{
		CurrNetcfg.vecPin = { "19" };
		CurrNetcfg.vecBps = { "250K" };
		CurrNetcfg.vecFilterId = { 0x0CFE6CEE,0x18FEC1EE,0x18FFDA17,0x18FFA017,0x18FFA117 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x8700000B)
	{
		CurrNetcfg.vecPin = { "19" };
		CurrNetcfg.vecBps = { "250K" };
		CurrNetcfg.vecFilterId = { 0x18FE4121,0x18FE4021,0x18FF0B21,0x0CFDCC21,0x18A9E821,0x18FED921,0x0C0BA021 };
		CurrNetcfg.vecFilterMask = { 0xFFFFFFFF };
	}
	else if (idm == 0x8700000C)
	{
		CurrNetcfg.vecPin = { "19" };
		CurrNetcfg.vecBps = { "250K" };
		CurrNetcfg.vecFilterId = { 0x0CF02FA0,0x10F007E8,0x18FE5BE8,0x18FECAE8,0x18FECAA0 };
	}
	else if (idm == 0x8700000D)
	{
		CurrNetcfg.vecFilterId = { 0x18FF6133,0x18FF6033,0x18FEF433,0x18FECA33 };
	}
	else if (idm == 0x8700000E)
	{
		CurrNetcfg.vecFilterId = { 0x18FF60FB,0x18FF61FB };
	}
	else if (idm == 0x8700000F)
	{
		CurrNetcfg.vecFilterId = { 0x18FFC13A };	
	}
	else if (idm == 0x87000010)
	{
		CurrNetcfg.vecFilterId = { 0x18FF7313, 0x18F0090B, 0x18FF7708, 0x18FF01A1, 0x18FFF202, 0x0CFF1402, 0x18FEF100, 0x18FF05A5, 0x18FFD105, 0x18FFF101, 0x18FFF603, 0x16FF02A2, 0x18FF03A3, 0x18FEC1EE };
	}
	else if (idm == 0x87000011)
	{
		CurrNetcfg.vecFilterId = { 0x16FF32C2, 0x16FF31C1 };
	}
	else if (idm == 0x87000012)
	{
		CurrNetcfg.vecFilterId = { 0x18FF26D1, 0x18FF21B1, 0x17FF22B2, 0x18FF23B3, 0x18FF24B4, 0x18FF25B5, 0x18FF26B6 };
	}
	else if (idm == 0x87000013)
	{
		CurrNetcfg.vecFilterId = { 0x18FF7111, 0x18FF7B1B, 0x18FF319E };
	}
	else if (idm == 0x87000014)
	{
		CurrNetcfg.vecFilterId = { 0x0C010305, 0x16FF42D2, 0x16FF41D1 };
	}
	else if (idm == 0x87000015)
	{
		CurrNetcfg.vecFilterId = { 0x18FF7E1E, 0x18FF80D5, 0x18FF843A, 0x18FFF703, 0x18FF823A, 0x18FF833A, 0x18FF853A };
	}
	else if (idm == 0x87000016)
	{
		CurrNetcfg.vecFilterId = { 0x18FF7919, 0x18FF791A, 0x18FFE419, 0x18FF9A19 };
	}
	else if (idm == 0x87000017)
	{
		CurrNetcfg.vecFilterId = { 0x18FFA0D8, 0x18FFA1D8 };
	}
	else if (idm == 0x87000018)
	{
		CurrNetcfg.vecFilterId = { 0x18FF319D, 0x18F0090B, 0x18FF319B, 0x18FF01A1, 0x18FFF202, 0x0CFF1402, 0x18FEF100, 0x0CFF05A1, 0x18FFD105, 0x18FFF101, 0x18FFF603, 0x0CFF02A1, 0x18FF03A3, 0x18FEC1EE };
	}
	else if (idm == 0x87000019)
	{
		CurrNetcfg.vecFilterId = { 0x0CFF32C1, 0x0CFF31C1 };
	}
	else if (idm == 0x8700001A)
	{
		CurrNetcfg.vecFilterId = { 0x18FF319A, 0x18FF7B1B, 0x18FF319E };
	}

	return EnterSystem_Listen();
}

CBinary SANYI_J1939::GetDsId(BYTE cmd)
{
	CBinary binId("\x00\x00\x00\x00\x00\x00", 6);
	binId[0] = m_root_id;
	binId[3] = cmd;
	return binId;
}

UINT SANYI_J1939::GetMenuIdx()
{
	if (m_Idm == 0x87000003)
		return MENU_JIANGSHAN_VCU;
	else if (m_Idm == 0x87000004)
		return MENU_QIXING_VCU;
	else if (m_Idm == 0x87000005)
		return MENU_QIXING_MCU;
	else if (m_Idm == 0x87000006)
		return MENU_QIXING_PDU;
	else if (m_Idm == 0x87000007)
		return MENU_QIXING_ABS;
	else if (m_Idm == 0x87000008)
		return MENU_QIXING_BMS;
	else if (m_Idm == 0x87000009)
		return MENU_QIXING_TCU;
	else if (m_Idm == 0x8700000A)
		return MENU_QIXING_IC;
	else if (m_Idm == 0x8700000B)
		return MENU_QIXING_BCM;
	else if (m_Idm == 0x8700000C)
		return MENU_QIXING_ADAS;
	else if (m_Idm == 0x8700000D)
		return MENU_QIXING_TPMS;
	else if (m_Idm == 0x8700000E)
		return MENU_QIXING_TBOX;
	else if (m_Idm == 0x8700000F)
		return MENU_QIXING_TMS;
	else if (m_Idm == 0x87000010)
		return MENU_JIANGSHAN_SWJ_VCU;
	else if (m_Idm == 0x87000011)
		return MENU_JIANGSHAN_SWJ_MCU;
	else if (m_Idm == 0x87000012)
		return MENU_JIANGSHAN_SWJ_BMS;
	else if (m_Idm == 0x87000013)
		return MENU_JIANGSHAN_SWJ_PDU;
	else if (m_Idm == 0x87000014)
		return MENU_JIANGSHAN_SWJ_TCU;
	else if (m_Idm == 0x87000015)
		return MENU_JIANGSHAN_SWJ_TMS;
	else if (m_Idm == 0x87000016)
		return MENU_JIANGSHAN_SWJ_AC;
	else if (m_Idm == 0x87000017)
		return MENU_JIANGSHAN_SWJ_BCC;
	else if (m_Idm == 0x87000018)
		return MENU_LINENG_VCU;
	else if (m_Idm == 0x87000019)
		return MENU_LINENG_MCU;
	else if (m_Idm == 0x8700001A)
		return MENU_LINENG_PDU;
	return 0;
}
BOOL SANYI_J1939::ShowNewDsUI(CBinary binId)
{
	StatusBox(TEXT_READING_CDS);
	m_binIndex = binId;//用于后面选择数据流使用,DBC工具代码
	while (1)
	{
		DataStream.Init();
		DataStream.SetNewUI();

		LoadDsItemViaDsIndex(binId);

		LoadDsRefVal();

		WORD nKey = -1;
		while (1)
		{
			HandleEachRoundDs();
			WORD nTop = 0;
			WORD nBottom = 0;
			DataStream.GetCurrentRange(nTop, nBottom);//获取当前屏的数据流
			if (nTop >= nBottom) {
				plt_log_printf("Warring : DataStream.GetCurrentRange(nTop, nBottom); nTop[%d] >= nBottom[%d]", nTop, nBottom);
			}
			for (int i = nTop; i < nBottom; i++)
			{
				CBinary idDataStream = DataStream.GetDataStream(i);
				TString strValue = "";
				if (PrepareReadOneDs(idDataStream, strValue) == FALSE) {
					strValue = "N/A";
				}
				if (idDataStream[3] == 0x01 && idDataStream[0] == 0x03)	
				{
					if (idDataStream[5] < 0x6D && idDataStream[5] > 0x52)
					{
						if (strValue == "0")
							DataStream.SetValue(idDataStream, strValue, "无故障");
						else
							DataStream.SetValue(idDataStream, strValue, strValue + "级故障");
					}
					else if (idDataStream[5] > 0x6C)
					{
						if (strValue == "0")
						{
							DataStream.SetValue(idDataStream, strValue, "灯灭");
						}
						else if((strValue == "1"))
						{
							DataStream.SetValue(idDataStream, strValue, "灯亮");
						}
						else
						{
							DataStream.SetValue(idDataStream, strValue, "--");
						}
					}
					else
					{
						if (strValue == "0")
						{
							DataStream.SetValue(idDataStream, strValue, "正常");
						}
						else if ((strValue == "1"))
						{
							DataStream.SetValue(idDataStream, strValue, "故障");
						}
						else
						{
							DataStream.SetValue(idDataStream, strValue, "--");
						}
					}
					DataStream.SetReferenceValue(idDataStream, "", "0", "0");
				}
				else
				{
					DataStream.SetValue(idDataStream, strValue);
				}
					
			}
			nKey = DataStream.Show();
			if (nKey == KEY_ESC)
				return TRUE;
			else if (nKey == KEY_CDS_SELECTED)
			{
				ShowDSMulSel();
				break;
			}
		}
	}

	return TRUE;

}