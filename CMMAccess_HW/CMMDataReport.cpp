#include "CMMDataReport.h"
#include "CMMMeteTranslate.h"
#include "CMMConfig.h"
#include "CMMProtocolEncode.h"
#include "SysCommon.h"
#include "CMMAccess.h"


namespace CMM
{
	CMMDataReport::CMMDataReport( int type )
	{
	}

	CMMDataReport::~CMMDataReport()
	{

	}

	//canyon
	int CMMDataReport::OnDataProcess(void*param )
	{
		/*if(param == NULL)
		{
			return -1;
		}
		BUSINESS::CMeter* pMeter = (BUSINESS::CMeter*)param;
		try
		{

		}
		catch(...)
		{
			
		}

		
		int SignalNumber = pMeter->m_CmmIdSignalNum;
		CData cmmId = pMeter->m_CmmBaseId;
		if(cmmId.length() == 0)
		{
			return -1;
		}
		CData deviceId = pMeter->m_cmmDevId;
		TSemaphore semphore={0};
		semphore.ID = cmmId;
		semphore.SignalNumber = SignalNumber;
		CMMConfig::instance()->GetSemaphoreConf(deviceId, semphore);
		
		pMeter->GetValue(semphore.MeasuredVal);
		semphore.Time = ISFIT::timeToString(ISFIT::getLocalTime());
		CData request = CMMProtocolEncode::BuildDataReport(deviceId, semphore);
		CMMAccess::instance()->SendRequestToServer(request);*/
		return 0;
	}
}


