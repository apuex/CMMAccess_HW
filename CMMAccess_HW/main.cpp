//canyon 2021 07 16

#include "main.h"
#include "CMMAccess.h"

#include "../../ExtAppIpc/ExtAppMain.hpp"


CData ExtAppVersion()
{
	return CMM::CMMAccess::instance()->describe();
}

void ExtAppInitParam(std::list<std::tuple<CData, CData> >& param)
{
	CMM::CMMAccess::instance()->initialize(param);
}


int ExtAppUpdateParam(std::map<CData, CData>& paramMap,std::map<CData,CData>& errorMap)
{
	return CMM::CMMAccess::instance()->UpdateParam(paramMap, errorMap);
}

int ExtAppMsgNotify(CData type, std::map<CData, CData>& msg)
{
	if (type == "store")
	{
		 CMM::CMMAccess::instance()->SaveDataLog(msg);
	}
	else if (type == "alarm")
	{
		CMM::CMMAccess::instance()->NotifyAlarm(msg);
	}
	else if (type == "meter")
	{

	}

	//LogInfo("type:"<<type);

	for (auto it=msg.begin(); it!=msg.end(); it++)
	{
		CData key = it->first;
		CData val = it->second;
		//LogInfo("key:"<<key<<" val:"<<val);
	}
	
	return 0;
}


int TestAODOCb(CData devId, CData meterId, CData val)
{
	LogInfo("devId:"<<devId<<" meterId:"<<meterId<<" val:"<<val);
	return 0;
}

int ExtAppMain(int argc, char* argv[])
{
	CData extAppName = argv[0];
	extAppName = extAppName.substring(extAppName.find_last_of("/", std::string::npos)+1, extAppName.find(".app"));
	
	ISFIT::tLogConfig config;
	CData logFileName = "/userdata/log/"+extAppName + ".log";
	config.logFileName =logFileName.c_str();
	ISFIT::CLog::Instance().init(config);
	
	CMM::CMMAccess::instance()->start();
	while(1)
	{
		Poco::Thread::sleep(100);
	}
	return 0;
}





