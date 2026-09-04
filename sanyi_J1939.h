
#ifndef _SANYI_J1939_H_
#define _SANYI_J1939_H_
#include "Diag.h"
#include "../HD_UTILS/code/SYS_BASE_FUNC.h"

class SANYI_J1939 : public CSYS_BASE_FUNC
{
public:
	SANYI_J1939();

protected:
	virtual BOOL ConnectSystem(UINT idm);

	virtual CBinary GetDsId(BYTE cmd);//系统数据流的IDX，派生类指定

	virtual UINT GetMenuIdx();

	virtual BOOL ShowNewDsUI(CBinary binDsIndex);

public: 
	UINT m_Idm = 0;
};

#endif // !defined(_SYS_BASE_FUNC_H_)
