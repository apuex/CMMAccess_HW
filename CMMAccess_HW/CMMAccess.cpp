
//canyon 2021 07 15 translate to extapp mode

#include "CMMAccess.h"
#include "CMMConfig.h"
#include "CMMDeviceConfig.h"
#include "CMMCommonStruct.h"
#include "SysCommon.h"
#include "CLog.h"
#include "CMMProtocolEncode.h"
#include "CMMMeteTranslate.h"
#include "CTextEncryption.h"
#include "Poco/File.h" 
#include "Poco/Path.h" 
#include "Poco/DirectoryIterator.h"
#include "Poco/DateTimeParser.h"
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <regex>
#include "Poco/RegularExpression.h"
#include "../../ExtAppIpc/ExtAppIpcApi.h"


const unsigned int CMM_MAX_RESPONSE_BUFFER_SIZE = 512*1024;


int SetAODOCb(CData devId, CData meterId, CData val)
{
	LogNotice("devId:" << devId << " meterId:" << meterId << " val:" << val);
	return 0;
}

namespace CMM{

	CMMAccess* CMMAccess::_instance = NULL;
	Poco::FastMutex CMMAccess::m_mutex;


	CMMAccess::CMMAccess()
	{
		m_bStart = false;
		m_bLoginOK = false;
		m_heartBeatTime = 300;
		m_registerStatus = CMM_REGISTER_FAILED;
		m_RightLevel = -1;
		m_registerTime = 60;
		m_nRetry = 0;
		
#ifdef ACCESSCONTROL
		m_udpServer = new CUdpServer();
		m_udpClient = new CUdpClient();
#else
		m_server = new CHttpServer();
		m_client = new CHttpClient();
#endif // ACCESSCONTROL
		
		m_webServer = new CWebServer();
	}
	
	CMMAccess* CMMAccess::instance()
	{
		if(_instance == NULL){
			Poco::FastMutex::ScopedLock lock(m_mutex);
			if(_instance == NULL){
				_instance = new CMMAccess();
			}
		}
		return _instance;
	}

	
	CData CMMAccess::GetIfcIp(CData ifcName)
	{		
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(struct ifreq));
		strcpy(ifr.ifr_name, ifcName.c_str());
		
		struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
		addr->sin_family = AF_INET;
		
		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		CData ipaddr;
		if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
		{
			ipaddr = inet_ntoa(addr->sin_addr);
		}
		close(fd);
		return ipaddr;
	}

	
	CData CMMAccess::GetLocalMac()  
	{  
		CData mac;
	    int sock_mac;  
	      
	    struct ifreq ifr_mac;  
	    char mac_addr[30];     
	      
	    sock_mac = socket( AF_INET, SOCK_STREAM, 0 );  
	    if( sock_mac == -1)  
	    {  
	        LogError("create socket falise...mac/n");  
	        return "" ;  
	    }  
	      
	    memset(&ifr_mac,0,sizeof(ifr_mac));     
	    strncpy(ifr_mac.ifr_name, "eth0", sizeof(ifr_mac.ifr_name)-1);     
	  
	    if( (ioctl( sock_mac, SIOCGIFHWADDR, &ifr_mac)) < 0)  
	    {  
	        LogError("mac ioctl error/n");  
	        return "";  
	    }  
	      
	    sprintf(mac_addr,"%02x:%02x:%02x:%02x:%02x:%02x",  
	            (unsigned char)ifr_mac.ifr_hwaddr.sa_data[0],  
	            (unsigned char)ifr_mac.ifr_hwaddr.sa_data[1],  
	            (unsigned char)ifr_mac.ifr_hwaddr.sa_data[2],  
	            (unsigned char)ifr_mac.ifr_hwaddr.sa_data[3],  
	            (unsigned char)ifr_mac.ifr_hwaddr.sa_data[4],  
	            (unsigned char)ifr_mac.ifr_hwaddr.sa_data[5]);  
	  
 	    close( sock_mac );  
	    mac = mac_addr;  
		return mac;
	}
	
	CData CMMAccess::GetNetIfcParam(CData ifconfig, CData key)
	{
		CData val;
		CData content = ifconfig;		
		CData pattern = key;
		
		int startPos = content.find(pattern);
		if (CDATA_NPOS != startPos)
		{
			int endPos =  content.find(" ", startPos+pattern.size());
			if (CDATA_NPOS != endPos)
			{
				val = content.substring(startPos+pattern.size(), endPos);
			}
		}
		return val;
	}
	
	
	void CMMAccess::AddRoute(CData destIp, CData gateWay)
	{
		
		if (gateWay == "eth0Gw")
		{
			//NETMODULE::T_NETCONFIGINFO cfg;
			//NETMODULE::GetNetCfg(cfg);
			//gateWay = cfg.localGw;
		}
		else if (gateWay == "ppp0Gw")
		{
			gateWay = GetNetIfcParam(ISFIT::Shell("ifconfig ppp0"), "P-t-P:");
		}
		else if (gateWay == "ppp1Gw")
		{
			gateWay = GetNetIfcParam(ISFIT::Shell("ifconfig ppp1"), "P-t-P:");
		}
	
		if (gateWay.size() > 0)
		{
			CData delRoute = "route del " + destIp;
			LogInfo("===>AddRoute() delRoute: "<<delRoute);
			ISFIT::Shell(delRoute.c_str());
					
			CData addRoute = "route add -net " + destIp + " netmask 255.255.255.255 gw " + gateWay;
			LogInfo("===>addRoute: "<<addRoute);
			ISFIT::Shell(addRoute.c_str());
		}
	
	}


	int CMMAccess::AddLinuxSysUser(CData user, CData passwd, CData dir)
	{	
		//system("mount -o remount,rw /");
		//Poco::Thread::sleep(500);
		if (user.empty()) return -1;
		
		FILE   *shellFile; 
		int ret = 0;
		CData cmd = "adduser " + user; 
		if (dir.size()>0)
		{
			cmd += " -h " + dir;
		}
		if (passwd.empty())
		{
			cmd += " -D";
		}
		
		if ((shellFile = popen(cmd.c_str(), "w") ) == nullptr) 
		{ 
			perror("popen");
			LogError("popen error:"<<strerror(errno));
			ret = -1; 
		} 
		else
		{
			LogInfo("Shell cmd: "<<cmd);
	
			if (passwd.size() > 0)
			{
				Poco::Thread::sleep(500);
				passwd += "\r";
				LogInfo("=====>shell write the passwd:"<<passwd);
				fwrite(passwd.c_str(), 1, passwd.size(), shellFile);
				
				Poco::Thread::sleep(500);
				LogInfo("=====>shell write the passwd again");
				fwrite(passwd.c_str(), 1, passwd.size(), shellFile);
			}
			
			if ((ret = pclose(shellFile)) == -1) 
			{ 
				LogError("close popen error, cmd:"<<cmd<<" ret:"<<ret);
				ret = -2;
			} 
		}
	
		//system("mount -o remount,ro /");
		//Poco::Thread::sleep(500);
		
		return ret;
	}
	
	int CMMAccess::DelLinuxSysUser(CData user)
	{	
		if (user.empty()) return -1;
		//system("mount -o remount,rw /");
		//Poco::Thread::sleep(500);
		
		CData cmd = "deluser " + user; 
		ISFIT::Shell(cmd);	
	
		//system("mount -o remount,ro /");
		//Poco::Thread::sleep(500);
		
		return 0;
	}
	
	
	
	int CMMAccess::ModifyLinuxSysPasswd(CData user, CData passwd)
	{	
		//system("mount -o remount,rw /");
		//Poco::Thread::sleep(500);
		if (user.empty() || passwd.empty()) return -1;

		
		FILE   *shellFile; 
		int ret = 0;
	
		CData cmd = "passwd " + user; 
		
		if ((shellFile = popen(cmd.c_str(), "w") ) == nullptr) 
		{ 
			perror("popen");
			LogError("popen error:"<<strerror(errno));
			ret = -1; 
		} 
		else
		{
			LogInfo("Shell cmd: "<<cmd);
			
			Poco::Thread::sleep(500);
			passwd += "\r";
			LogInfo("=====>modify passwd:"<<passwd);
			fwrite(passwd.c_str(), 1, passwd.size(), shellFile);
			
			Poco::Thread::sleep(500);
			LogInfo("=====>modify passwd again");
			fwrite(passwd.c_str(), 1, passwd.size(), shellFile);
			
			if ((ret = pclose(shellFile)) == -1) 
			{ 
				LogError("close popen error, cmd:"<<cmd<<" ret:"<<ret);
				ret = -2;
			} 
		}
	
		//system("mount -o remount,ro /");
		//Poco::Thread::sleep(500);
		
		return ret;
	}

	void CMMAccess::SaveDataLog(std::map<CData, CData>& msg)
	{
		m_datalog.Save(msg);
	}
	
	void CMMAccess::SetLoginState(bool isLoginOk)
	{
		CData state = isLoginOk ? "成功" : "失败";
		m_bLoginOK = isLoginOk;
		CData oldState = CMMConfig::instance()->GetParam(CMM::param::LoginState, "");
		if (oldState != state)
		{
			CMMConfig::instance()->SetParam(CMM::param::LoginState, state);
		}
		CData newState = CMMConfig::instance()->GetParam(CMM::param::LoginState, "");
		LogInfo("newState: " << newState.c_str());
	}

	void CMMAccess::Test()
	{
		CData devID;
		//APPAPI::DelDev("069500000000001");
		while (0)
		{
			devID = "069500000000001";
			//APPAPI::DelDev("069500000000002");
			//devID = APPAPI::CreateDev("移动B接口测试设备","移动B接口测试",true,"", SetAODOCb);

			std::map<CData, CData> paramMaps;
			paramMaps["aliasDevName"] = "999999";
			paramMaps["aliasDevId"] = "999999";
			paramMaps["gatewayId"] = "local";
			int ret = APPAPI::SetDevParam(devID, "alias", paramMaps);
			LogInfo("============SetDevParam return" << ret);
			/*std::list<CData> meterIdList;
			meterIdList.push_back("001018001");
			int ret = APPAPI::CreateMeter(devID, meterIdList);
			LogInfo("============CreateMeter return " << ret);*/
		
			std::list<std::map<CData,CData> > paramList;
				std::map <CData, CData> meterParamMap;
				meterParamMap["meterId"] = "001018001";
				meterParamMap["threshold"] = CData(88);
				meterParamMap["alarmLevel"] = CData(2);
				paramList.push_back(meterParamMap);
			std::list<CData> errorMeterIdList;
			ret = APPAPI::SetMeterParam(devID, "msj", paramList, errorMeterIdList, 5000);
			LogInfo("============SetMeterParam return:"<<ret);


			ret = APPAPI::SetMeterVal(devID, "001018001", "msj", CData(0), true);
			LogInfo("============SetMeterVal return: " << ret);


			std::map<CData,CData> paramMap;
			ret = APPAPI::GetMeterParam(devID, "001018001", "msj",paramMap);
			LogInfo("============GetMeterParam " << paramMap.size() << " ret:" << ret);

			for(auto it=paramMap.begin(); it!=paramMap.end(); it++)
			{
				LogInfo("==key:"<<it->first<<" val:"<<it->second);
			}

			std::set<CData> attrSet;
			attrSet.insert("meterId");
			attrSet.insert("meterType");
			attrSet.insert("alarmLevel");
			attrSet.insert("threshold");
			//attrSet.insert("meterName");
			std::list<std::map<CData,CData> > infoList;
			ret = APPAPI::GetMeterInfo(devID, "msj", attrSet, infoList, 10000);
			LogInfo("============GetMeterInfo" << infoList.size() << " ret:" << ret);
			for (auto mit=infoList.begin(); mit!=infoList.end(); mit++)
			{		
				std::map<CData,CData>& attr = *mit;
				CData meterId=attr["meterId"];
				for(auto it=attr.begin(); it!=attr.end(); it++)
				{
					if (meterId == "001018001")
						LogInfo("==key:"<<it->first<<" val:"<<it->second);
				}
			}

			CMMConfig::instance()->UpdateCfgFile();
			Poco::Thread::sleep(3000);
		}
		
		if (0)
		{
			LogInfo("============test1===========")
			std::map<CData,CData> paramMap;
			APPAPI::GetMeterParam(devID, "020010001", "alias",paramMap);
			for(auto it=paramMap.begin(); it!=paramMap.end(); it++)
			{
				LogInfo("==key:"<<it->first<<" val:"<<it->second);
			}
		}
		if (0)
		{
			LogInfo("============test2===========")
			std::list<std::map<CData,CData> > paramList;
			APPAPI::GetMeterParam(devID, "alias",paramList);
			for(auto it=paramList.begin(); it!=paramList.end(); it++)
			{
				LogInfo("======##############=====")
				std::map<CData,CData>& attr = *it;
				for (auto ait=attr.begin(); ait!=attr.end(); ait++)
					LogInfo("==key:"<<ait->first<<" val:"<<ait->second);
			}
		}
		
		if (1)
		{
			std::map<CData, std::list<TSemaphore>> reqDevMap;
			CMMConfig::instance()->GetSemaphoreConf(reqDevMap);
			CData sendBuffer = CMMProtocolEncode::BuildDataReportTest(reqDevMap);
			CData responseData;
			int nRet  = m_udpClient->SendXmlData(m_scEndPoint.c_str(), sendBuffer, responseData);
			if (responseData.size() <= 0 || nRet < 0)
			{
				LogError("SendXmlData error." << nRet);
				return;
			}
		}
	}

	void CMMAccess::UpdateModuleInfo()
	{
		CData fsuId = CMMConfig::instance()->GetFsuId();
		CData fsuIp = CMMConfig::instance()->GetFsuIp();

		APPAPI::SetMeterVal(CData("215001"), CData("138131001"), "msj", fsuIp);
		APPAPI::SetMeterVal(CData("215001"), CData("138127001"), "msj", fsuId);
		/*APPAPI::SetMeterVal(CData("215001"), CData("004001001"), "msj", "1");
		APPAPI::SetMeterVal(CData("215001"), CData("004002001"), "msj", "0");
		APPAPI::SetMeterVal(CData("215001"), CData("004301001"), "msj", "20");
		APPAPI::SetMeterVal(CData("215001"), CData("004304001"), "msj", "40");
		APPAPI::SetMeterVal(CData("215001"), CData("005101001"), "msj", "0");
		APPAPI::SetMeterVal(CData("215001"), CData("006201001"), "msj", "50");
		APPAPI::SetMeterVal(CData("215001"), CData("007401001"), "msj", "1");*/

	}

	void CMMAccess::run()
	{
#ifdef ACCESSCONTROL
		m_registerStatus = CMM_REGISTER_SUCCESS;
		while (m_bStart)
		{
			Poco::Timestamp now;
			time_t diff = now.epochTime() - m_lastMsgTime.epochTime();
			if (diff >= m_registerTime || CMMConfig::instance()->m_bUpdate)
			{
				std::map<CData, std::list<TSemaphore>> mapSem;
				ReportDevConf();
				NotifySendData(mapSem);
				CMMConfig::instance()->m_bUpdate = false;
				m_lastMsgTime.update();
			}
			ReportAlarms();
			Test();
			Poco::Thread::sleep(1000* 3);
		}
#else
		//Test();	
		SetLoginState(false);//默认登录不成功
		Poco::Timestamp dataCheckTime;
		UpdateModuleInfo();
		while(m_bStart)
		{			
			Poco::Timestamp now;
			time_t diff = now.epochTime() - m_lastMsgTime.epochTime();
			if(CMM_REGISTER_FAILED == m_registerStatus)
			{
				if(diff >= m_registerTime && m_nRetry <= 3)
				{
					Login();
					m_lastMsgTime.update();
					m_nRetry++;
				}
				if (m_nRetry > 3)    //失败超过3次 3分钟重试一次
				{
					if (diff >= 180)
					{
						Login();
						m_lastMsgTime.update();
					}		
				}
			}
			else
			{
				if (CMMConfig::instance()->m_bUpdate)//重新登录后要判断是否有更新
				{
					std::map<CData, std::list<TSemaphore>> mapSem;
					ReportDevConf();
					NotifySendData(mapSem);
					CMMConfig::instance()->m_bUpdate = false;
				}
				ReportAlarms();
				m_nRetry = 0;
				if(diff >= (m_heartBeatTime*3))
				{
					SetLoginState(false);
					Login();
				}
			}
			Poco::Thread::sleep(500);
		}
#endif // DEBUG
	}
	
	void CMMAccess::Init()
	{			
		SetPowerdownAlarmParam(10);		
		m_recoverPowerdownAlarmParamTimer = new ISFIT::CTimer(this, &CMMAccess::SetPowerdownAlarmParam, 1000*10, false, 0);
		m_updateDevTimer = new ISFIT::CTimer(this, &CMMAccess::UpdateDevConf, 1000*30, true, 0);
		m_wirteMeasurementFileTimer = new ISFIT::CTimer(this, &CMMAccess::WriteMeasureFile, 1000 * 60, true, 0);

		m_registerStatus = CMM_REGISTER_FAILED;
	
		CMMDeviceConfig::instance()->Init();
		CMMConfig::instance()->Init();
		
#ifdef ACCESSCONTROL
		m_scEndPoint = "udp://" + CMMConfig::instance()->GetParam(CMM::param::SCIp, "1.1.1.1") + ":"
			+ CMMConfig::instance()->GetParam(CMM::param::SCPort, "80") + "/v1/services/newLSCService";//LSCService
#else 
		m_scEndPoint = "http://" + CMMConfig::instance()->GetParam(CMM::param::SCIp, "1.1.1.1") + ":"
			+ CMMConfig::instance()->GetParam(CMM::param::SCPort, "80") + "/v1/services/newLSCService";//LSCService
#endif
		
		
		m_fsuEndPoint = CMMConfig::instance()->GetParam(CMM::param::FSUEndPoint, "/v1/services/newFSUService");
	
		m_heartBeatTime =  CMMConfig::instance()->GetParam(CMM::param::HeartBeatTimeout, "300").convertInt();

		m_registerTime = CMMConfig::instance()->GetParam(CMM::param::LoginTimeout, "60").convertInt();

		m_wirteFileTime = CMMConfig::instance()->GetParam(CMM::param::GetMeasurementTime, "15").convertInt();

		int fsuPort = CMMConfig::instance()->GetParam(CMM::param::FSUPort, "8443").convertInt();
		int webPort = CMMConfig::instance()->GetParam(CMM::param::WebPort, "8080").convertInt();
		//int udpPort = CMMConfig::instance()->GetParam(CMM::param::UdpPort, "1234").convertInt();
			
		
		m_webServer->Start(webPort);
		
#ifdef ACCESSCONTROL
		m_udpServer->Start(fsuPort);
		m_udpClient->Start();
#else // DEBUG
		m_server->Start(fsuPort, m_fsuEndPoint);
		m_client->Start();
#endif
	}

	

	void CMMAccess::UpdateInterval(CData interval)
	{
		m_heartBeatTime=interval.convertInt();
		CMMConfig::instance()->m_heartbeatTimeout=interval;
		CMMConfig::instance()->SetParam(CMM::param::HeartBeatTimeout, interval);
	}

	void CMMAccess::OnHeartBeat()
	{
		m_lastMsgTime.update();
	}

	void CMMAccess::Login()
	{
	
		//AddRoute(CMMConfig::instance()->m_scIp,CMMConfig::instance()->m_scIpRoute);
		
		CData loginInfo = CMMProtocolEncode::BuildLogMsg();

		CData auth_header,token;
		UpdateAuthHeader(loginInfo, auth_header, token);
		Poco::FastMutex::ScopedLock lock(m_mutex);
	
		HTTPResponse response;
		CData responseData;
		int nRet = m_client->SendXmlData(m_scEndPoint.c_str(), loginInfo, auth_header, response, responseData);
		if (nRet < 0)
		{
			if (nRet == -3)
			{
				m_nRetry = 5; //超时 直接置为大于3值 300s重试
			}
			m_registerStatus = CMM_REGISTER_FAILED;
			SetLoginState(false);
			return;
		}	
		if(nRet != 200)
		{			
			m_registerStatus = CMM_REGISTER_FAILED;
			SetLoginState(false);
			return ;
		}
		int ret = m_msgProcess.OnMsgProcess((char*)responseData.c_str(), NULL, 0);
		if(ret == 1)
		{
			static bool bFirstReadDev=true;
			if(bFirstReadDev)////第一次登录后读一次列表，确保设备全部读取完整
			{
				bFirstReadDev=false;
				//CMMConfig::instance()->UpdateCfgFile();
				CMMConfig::instance()->OnUpdateCfgFileTimer();
				CMMConfig::instance()->WriteMeasurefile();	
			}
			m_registerStatus = CMM_REGISTER_SUCCESS;
			SetLoginState(true);
			m_RightLevel = ret;
			
			LogInfo("====Login ok ===");
			m_lastMsgTime.update();
		}
		else if (ret == 3) //token 或 认证出错
		{
			m_registerStatus = CMM_REGISTER_FAILED;
			SetLoginState(false);
			LogError("cmm login failed verify to Authorization :" << ret);
		}
		else
		{
			m_registerStatus = CMM_REGISTER_FAILED;
			SetLoginState(false);
			LogError("cmm login faild right level:"<<ret);
		}		
	}

	int CMMAccess::DoMsgProcess( char* request, char* response, int size )
	{
		LogInfo(" recv request:"   << request);
		memset(response,0,strlen(response));
		return m_msgProcess.OnMsgProcess(request, response, size);
	}

	int CMMAccess::DoMsgProcess_Error(char* request, char* response, int size)
	{
		LogInfo("recv request error:" << request);
		memset(response, 0, strlen(response));
		return m_msgProcess.OnMsgProcess_Error(request, response, size);
	}

	void CMMAccess::ReportDevConf()
	{
#ifdef ACCESSCONTROL
		CData responseData;
		CData devInfo = CMMProtocolEncode::ReportDevConf();
		int nRet = m_udpClient->SendXmlData(m_scEndPoint.c_str(), devInfo, responseData);
		if (responseData.size() <= 0 || nRet < 0)
		{
			LogError("SendXmlData DevConf error.");
			return;
		}
#else 

		if (m_registerStatus != CMM_REGISTER_SUCCESS)
		{
			return ;
		}
		CData devInfo = CMMProtocolEncode::ReportDevConf();
		Poco::FastMutex::ScopedLock lock(m_mutex);
		CData auth_header, token, responseData;
		HTTPResponse response;
		UpdateAuthHeader(devInfo, auth_header, token);
		int nRet = m_client->SendXmlData(m_scEndPoint.c_str(), devInfo, auth_header, response, responseData);
		if (nRet < 0)
		{
			LogError("SendXmlDatav DevConf error.");
			return;
		}
		if (nRet != 200)
		{

			LogError("send service recv code:" << nRet << " reason:" << response.getReason().c_str());
			return;
		}
#endif
	}

	void CMMAccess::ReportAlarms()
	{
		Poco::FastMutex::ScopedLock lock(m_alarmMutex);
		if(m_alarmList.size() == 0)
		{
			return ;
		}
		CData reportInfo = CMMProtocolEncode::BuildAlarmReportInfo(m_alarmList);
		if(SendRequestToServer(reportInfo) == 0)
		{
			std::list<TAlarm>::iterator pos = m_alarmList.begin();
			while(pos != m_alarmList.end())
			{
				m_alarmList.erase(pos++);				
			}
		}
	}

	void CMMAccess::ReportData(std::map<CData, std::list<TSemaphore>> &mapSem)
	{
		
		CData reportInfo = CMMProtocolEncode::BuildDataReport(mapSem);
		SendRequestToServer(reportInfo);
	}

	int CMMAccess::FromAlarmInfoToTAlarm2(std::map<CData, CData>& msg, TAlarm& alarm )
	{
		std::vector<int> IgAlarmLevelVec=CMMConfig::instance()->GetIgnoreAlarmLevel();
		int iAlarmLevel=msg["alarmLevel"].convertInt();
		if(std::find(IgAlarmLevelVec.begin(),IgAlarmLevelVec.end(),iAlarmLevel)!=IgAlarmLevelVec.end())
		{
			//查找到要过滤的
			LogInfo("~~~~~~~~~~~~find IgnoreAlarmLevel, meterID:" << msg["meterId"]<<" AlarmLevel:"<<msg["alarmLevel"]<<" Config:"<<CMMConfig::instance()->m_IgnoreAlarmLevel);
			return -1;
		}	

		//key: serialNO devId meterId alarmLevel alarmFlag(begin,end) describe time triggerVal
		CData serialNO= msg["serialNO"];
		CData devId= msg["devId"];
		CData meterId= msg["meterId"];
		CData alarmLevel= msg["alarmLevel"];
		CData alarmFlag= msg["alarmFlag"];
		if (alarmFlag.compare("0") == 0 || alarmFlag.compare("begin") ==0)
			alarmFlag = "BEGIN";
		else if (alarmFlag.compare("1") == 0 || alarmFlag.compare("end") == 0)
			alarmFlag = "END";
		CData describe= msg["describe"];
		CData time= msg["time"];
		CData triggerVal= msg["triggerVal"];

		int len=meterId.length();
		alarm.ID = meterId.substr(0, len - 3);
		alarm.SignalNumber = meterId.substr(len - 3, 3).convertInt();
		LogInfo("=======>> CMMAccess ====> NotifyAlarm  meterId:"<<meterId);
		if(alarm.ID.length() == 0)
		{
			return -1;
		}

		CData aliasDevId;
		std::map<CData,CData> paramMap;
		if (APPAPI::GetDevParam(devId, "msj",paramMap)>=0)
		{
			aliasDevId= paramMap["aliasDevId"];
		}


		if(aliasDevId.size()==0)
		{
			LogInfo("=======>> CMMAccess ====> aliasDevId is NULL. ");
			return -1;
		}
		
		alarm.DeviceID = aliasDevId;
		
		alarm.SerialNo =serialNO;
		

		alarm.NMAlarmID = CMMConfig::instance()->NMAlarmID(alarm.ID);
		
		alarm.AlarmTime = time;		
		alarm.AlarmFlag = alarmFlag;
		alarm.AlarmLevel = alarmLevel.convertInt();	
		CData trigger = triggerVal;
		//alarm.AlarmDesc = describe+trigger;
		alarm.AlarmDesc = describe;
		alarm.EventValue = trigger.convertDouble();
		
		CData id=meterId.substr(0,3);
		int iID=id.convertInt();

		if(len>3&&Is_rangeAlarm(iID))
		{	
		//	alarm.AlarmRemark1 = meterId;//暂不填写
			//alarm.AlarmRemark2 = triggerVal;
		}
		else
		{
			LogInfo("error alarm meterId:"<<meterId);
			return -1;
		}
		
		return 0;
	}

	int CMMAccess::GetServerStatus( TServerStatus& sts )
	{
		sts.Status = ((m_registerStatus == CMM_REGISTER_SUCCESS)?"Register Success":"Register Failed");
		sts.lastHeartBeatTime = ISFIT::timeToString(m_lastMsgTime.epochTime());
		sts.RightLevel = m_RightLevel;
		return 0;
	}

	int CMMAccess::SendRequestToServer( CData &reportInfo)
	{
#ifdef ACCESSCONTROL
		CData responseData;
		int nRet = m_udpClient->SendXmlData(m_scEndPoint.c_str(), reportInfo, responseData);
		if (nRet < 0)
		{
			LogError("SendXmlData error.");
			return -1;
		}
		ISFIT::CXmlDoc doc;
		if (doc.Parse(responseData.c_str()) < 0)
		{
			return -1;
		}
		ISFIT::CXmlElement element = doc.GetElement(CMM::Response);
		ISFIT::CXmlElement Info = element.GetSubElement(CMM::Info);
		int result = Info.GetSubElement("Result").GetElementText().convertInt();
		if (result == 1)
		{
			return 0;
		}
		else
		{
			return -1;
		}
#else
		if(m_registerStatus != CMM_REGISTER_SUCCESS)
		{
			return -1;
		}
		Poco::FastMutex::ScopedLock lock(m_mutex);
		CData auth_header, token, responseData;
		HTTPResponse response;
		UpdateAuthHeader(reportInfo, auth_header, token);
		int nRet = m_client->SendXmlData(m_scEndPoint.c_str(), reportInfo, auth_header, response, responseData);
		if (nRet < 0)
		{
			LogError("SendXmlData error.");
			return -1;
		}
		if (nRet != 200)
		{

			LogError("send service recv code:" << nRet << " reason:" << response.getReason().c_str());
			return -1;
		}
		ISFIT::CXmlDoc doc;
		if(doc.Parse(responseData.c_str()) < 0)
		{
			return -1;
		}
		ISFIT::CXmlElement element = doc.GetElement(CMM::Response);
		ISFIT::CXmlElement Info = element.GetSubElement(CMM::Info);
		int result = Info.GetSubElement("Result").GetElementText().convertInt();
		if(result == 1)
		{
			return 0;
		}
		else
		{
			return -1;
		}
#endif
	}

	void CMMAccess::UpdateDevConf(int arg)
	{
		if(CMMConfig::instance()->OnUpdateCfgFileTimer())
		{
			//ReportDevConf();
			CMMConfig::instance()->m_bUpdate = true;				
		}
	}

	Poco::Timestamp parseTimestamp(const std::string& timestampStr) 
	{
		std::tm tmStruct = {};
		int year, month, day, hour, minute;
		
		if (sscanf(timestampStr.c_str(), "%04d%02d%02d%02d%02d", &year, &month, &day, &hour, &minute) == 5) 
		{
			tmStruct.tm_year = year - 1900; // tm_year 是从1900年开始计数的  
			tmStruct.tm_mon = month - 1;     // tm_mon 是从0开始的  
			tmStruct.tm_mday = day;
			tmStruct.tm_hour = hour;
			tmStruct.tm_min = minute;
			tmStruct.tm_sec = 0; // 秒数默认为0  
			tmStruct.tm_isdst = -1; // 让mktime决定是否为夏令时  

			// 将tm结构体转换为time_t（Unix时间戳）  
			time_t t = mktime(&tmStruct);
			return Poco::Timestamp::fromEpochTime(t);

		}
		// 解析失败，返回默认或错误的Poco::Timestamp  
		return Poco::Timestamp();
	}

	// 将文件名中的时间戳解析为 Poco::Timestamp  
	Poco::Timestamp parseTimestampFromFileName(const std::string& fileName)
	{
		size_t separator1 = fileName.find("_");  // 找到第一个下划线的位置
		if (separator1 != std::string::npos)
		{
			size_t separator2 = fileName.find("_", separator1 + 1);  // 找到第二个下划线的位置
			if (separator2 != std::string::npos)
			{
				CData datetimeStr = fileName.substr(separator2 + 1, 12);  // 提取日期时间部分
				int year = datetimeStr.substr(0, 4).convertInt();
				int month = datetimeStr.substr(4, 2).convertInt();
				int day = datetimeStr.substr(6, 2).convertInt();
				int hour = datetimeStr.substr(8, 2).convertInt();
				int minute = datetimeStr.substr(10, 2).convertInt();
				// 现在你可以使用year, month, day, hour, minute进行进一步操作
				//LogInfo("file:" << fileName << " hour:" << hour << " minute:" << minute);
				std::tm tmStruct = {};
				tmStruct.tm_year = year - 1900; // tm_year 是从1900年开始计数的  
				tmStruct.tm_mon = month - 1;     // tm_mon 是从0开始的  
				tmStruct.tm_mday = day;
				tmStruct.tm_hour = hour;
				tmStruct.tm_min = minute;
				tmStruct.tm_sec = 0; // 秒数默认为0  
				tmStruct.tm_isdst = -1; // 让mktime决定是否为夏令时  
				time_t t = mktime(&tmStruct);
				return Poco::Timestamp::fromEpochTime(t);
			}
		}
		throw std::invalid_argument("Invalid file name format: " + fileName);
	}

	// 删除指定目录下超过三天的文件  
	void deleteOldFiles() 
	{
		Poco::File dir("/Measurement");
		if (dir.exists() && dir.isDirectory())
		{
			// 获取当前UTC时间戳
			time_t nowInSeconds = std::time(nullptr);
			// 计算三天前的时间戳（以秒为单位）
			time_t threeDaysAgoInSeconds = nowInSeconds - (3 * 24 * 60 * 60); // 减去3天
			// 将时间戳转换为Poco::Timestamp对象
			Poco::Timestamp threeDaysAgo = Poco::Timestamp::fromEpochTime(threeDaysAgoInSeconds);
			Poco::DirectoryIterator it(dir.path());
			Poco::DirectoryIterator end;
			Poco::Path filePath;
			while (it != end)
			{
				if (it->isFile())
				{
					try 
					{
						filePath.assign(it->path());
						Poco::Timestamp fileTimestamp = parseTimestampFromFileName(filePath.getBaseName());
						// 尝试从文件名中解析时间戳
						if (fileTimestamp < threeDaysAgo && fileTimestamp!=0)
						{
							Poco::File oldFile(it->path());
							if (oldFile.exists()) 
							{
								oldFile.remove();
								LogInfo("Deleted: "<< it->path());
							}
						}
					}
					catch (const std::exception& e) 
					{
						LogError("Error processing file: " << filePath.getBaseName() << ", " << e.what());
					}
				}
				it++;
			}
		}
	}

	void CMMAccess::WriteMeasureFile(int arg)
	{
		static int nCount = 1;
		//LogInfo("nCount: "<< nCount << "   m_wirteFileTime :" << m_wirteFileTime);	
		if(nCount >= m_wirteFileTime)
		{
			//std::map<CData, std::list<TSemaphore>> mapSem;
			deleteOldFiles();//执行写文件之前判断是否有3天前的文件 有则删除
			if (CMMConfig::instance()->WriteMeasurefile())
			{
				//NotifySendData(mapSem); //写监控文件后发送SEND_DATA同步
				nCount = 0;
			}		
		}
		nCount++;
	}
	
	void CMMAccess::SetPowerdownAlarmParam(int arg)
	{
		//power down alarm
		std::map<CData, CData> paramMap;
		paramMap["alarmDlyTime"] = CData(arg);
		paramMap["alarmClearDlyTime"] = CData(arg);
		APPAPI::SetMeterParam("111001", "118336001","msj", paramMap);
	}


	void CMMAccess::NotifyAlarm(std::map<CData, CData>& msg)
	{	
		std::list<CData> devIdList;
		APPAPI::GetDevId("msj", devIdList);
		LogInfo("=======>> CMMAccess ====> NotifyAlarm== devIdList size:"<<devIdList.size());
		if(msg.size()>0)		
		{	
			CData seq; 
			{
				auto it=msg.find("serialNO");
				if (it!=msg.end()) seq = it->second;
			}
			LogInfo("=======>> CMMAccess ====> NotifyAlarm== seq:"<<seq);
			TAlarm alarm = {0};
			if(FromAlarmInfoToTAlarm2(msg, alarm) == 0)
			{		
				Poco::FastMutex::ScopedLock lock(m_alarmMutex);
				std::list<TAlarm>::iterator pos = m_alarmList.begin();
				while(pos != m_alarmList.end())
				{
					if(pos->SerialNo == seq)
					{
						if(pos->retryTimes == 0)
						{
							m_log.log(alarm);
							m_alarmList.erase(pos);
							LogInfo("=======>> CMMAccess ====>m_alarmList.erase seq:"<<seq);
							return;
						}
					}
					pos++;
				}
				m_alarmList.push_back(alarm);
				m_log.log(alarm);
				LogInfo("=======m_alarmList.push_back:"<<seq);
			}
		}
	}

	void CMMAccess::NotifySendData(std::map<CData, std::list<TSemaphore> >& mapSem)
	{
		if (mapSem.size() == 0)
		{
			CMMConfig::instance()->GetSemaphoreConf(mapSem);
		}
		/*std::map<CData, std::list<TSemaphore>> mapSem;
		CMMConfig::instance()->GetSemaphoreConf(mapSem);*/
		/*if (1)
		{
			for (auto it = mapSem.begin(); it != mapSem.end(); ++it)
			{
				CData devId = it->first;
				std::list<TSemaphore> semInfos = it->second;
				std::list<TSemaphore>::iterator iter = semInfos.begin();
				LogNotice("send data devid:" << devId.c_str());
				while (iter != semInfos.end())
				{
					TSemaphore seminfo = *iter;
					LogNotice("semInfo -- id:" << seminfo.ID.c_str() << " number:" << seminfo.SignalNumber);
					LogNotice("semInfo -- SetupVal:" << seminfo.SetupVal << " MeasuredVal:" << seminfo.MeasuredVal);
					iter++;
				}
			}
		}*/
		ReportData(mapSem);
	}

	void CMMAccess::SetAlarmDlyTime(CData dlyTime1, CData clearDlyTime1,
										CData dlyTime2, CData clearDlyTime2,
										CData dlyTime3, CData clearDlyTime3)
	{
		std::list<CData> devIdList;
		APPAPI::GetDevId("msj", devIdList,2000);
		//LogInfo("SetAlarmDlyTime() dlyTime:"<<dlyTime<<" clearDlyTime:"<<clearDlyTime);
		for (auto it=devIdList.begin(); it!=devIdList.end(); it++)
		{
			CData devId = *it;
			//std::list<std::map<CData,CData> > valList;
			//APPAPI::GetMeterVal(devId, "msj", valList, 10000);

			std::multimap<CData,CData> attrCondition;
			attrCondition.insert(std::pair<CData,CData>("meterId",""));
			//attrCondition.insert(std::pair<CData,CData>("meterType","DI"));
			attrCondition.insert(std::pair<CData,CData>("alarmLevel","1"));
			attrCondition.insert(std::pair<CData,CData>("alarmLevel","2"));
			attrCondition.insert(std::pair<CData,CData>("alarmLevel","3"));

			std::list<std::map<CData,CData> > infoList;
			// APPAPI::GetMeterInfo(devId, "msj","or",attrCondition, infoList, 10000);
			// DAHAI 未发现调用，暂时不管

			LogInfo("devId:"<<devId);
			
			std::list<std::map<CData,CData> > paramList;
			for (auto vit=infoList.begin(); vit!=infoList.end(); vit++)
			{
				std::map<CData,CData>& attr = *vit;
				for (auto ait=attr.begin(); ait!=attr.end(); ait++)
				{
					//LogInfo("==key:"<<ait->first<<" val:"<<ait->second);	
				}
				
				CData meterId = attr["meterId"];
				CData meterType = attr["meterType"];
				CData alarmLevel = attr["alarmLevel"];
				CData id=meterId.substr(0,3);
				//int iID=id.convertInt();

				//LogInfo("meterId:"<<meterId<<" meterType:"<<meterType<<" alarmLevel:"<<alarmLevel);
				if (meterId.size()>3 && (alarmLevel=="1"))
				{
					std::map<CData,CData> attrMap;
					attrMap["meterId"] = meterId;
					attrMap["alarmDlyTime"] = dlyTime1;
					attrMap["alarmClearDlyTime"] = clearDlyTime1;
					paramList.push_back(attrMap);
				}
				else if (meterId.size()>3 && (alarmLevel=="2"))
				{
					std::map<CData,CData> attrMap;
					attrMap["meterId"] = meterId;
					attrMap["alarmDlyTime"] = dlyTime2;
					attrMap["alarmClearDlyTime"] = clearDlyTime2;
					paramList.push_back(attrMap);
				}
				else if (meterId.size()>3 && (alarmLevel=="3"))
				{
					std::map<CData,CData> attrMap;
					attrMap["meterId"] = meterId;
					attrMap["alarmDlyTime"] = dlyTime3;
					attrMap["alarmClearDlyTime"] = clearDlyTime3;
					paramList.push_back(attrMap);
				}
			}
			std::list<CData> errorMeterIdList;
			APPAPI::SetMeterParam(devId, "msj", paramList, errorMeterIdList,0);
			
		}		
	}
	
	void CMMAccess::TestStart(int arg)
	{
	
	}

	void CMMAccess::initialize(std::list<std::tuple<CData, CData> >& param)
	{
		CData appDataDir = "/appdata";
		CData userDataDir = "/userdata";

		CData userPicDir=userDataDir+"/PIC";
		Poco::File userPicPath(userPicDir.c_str());
		if (userPicPath.exists() == false)
		{
			ISFIT::Shell("mkdir -m 777 " + userPicDir);
			LogInfo("======userPicPath:"<<userPicDir<<" not exists, create it===");
		}
		
		Poco::File picLnDir("/PIC");
		if (picLnDir.exists() == false)
		{
			ISFIT::Shell("ln -s " + userPicDir + "  /PIC");
			LogInfo("======/PIC not exists, create it====");
		}
		
		//真实创建
		CData usercmmDir=userDataDir+"/Config";
		Poco::File usercmmPath(usercmmDir.c_str());
		if (usercmmPath.exists() == false)
		{
			ISFIT::Shell("mkdir -m 777 " + usercmmDir);
			LogInfo("======usercmmPath:"<<usercmmDir<<" not exists, create it===");
		}

		Poco::File cmmLnDir("/Config");
	/*		if (cmmLnDir.exists() ==true)
		{
			ISFIT::Shell("rm -rf  /Config");
			LogInfo("======/Config not exists, create it====");
		}*/
		
		if (cmmLnDir.exists() == false)
		{
			ISFIT::Shell("ln -s " + usercmmDir + "  /Config");
			LogInfo("======/Config not exists, create it====");
		}
		
		//软链接
		CData userAlarmDir=userDataDir+"/Alarm";
		Poco::File userAlarmPath(userAlarmDir.c_str());
		if (userAlarmPath.exists() == false)
		{
			ISFIT::Shell("mkdir -m 777 " + userAlarmDir);
			LogInfo("======userAlarmPath:"<<userAlarmDir<<" not exists, create it===");
		}
		
		Poco::File alarmLnDir("/Alarm");
		if (alarmLnDir.exists() == false)
		{
			ISFIT::Shell("ln -s " + userAlarmDir + "  /Alarm");
			LogInfo("======/Alarm not exists, create it====");
		}
		
	//软链接
		Poco::File logsLnDir("/logs");
		if (logsLnDir.exists() == false)
		{
			ISFIT::Shell("ln -s /userdata/log/  /logs");
			LogInfo("======/logs not exists, create it====");
		}
		
		//软链接
		CData userMeasureDir=userDataDir+"/Measurement";
		Poco::File userMeasurePath(userMeasureDir.c_str());
		if (userMeasurePath.exists() == false)
		{
			ISFIT::Shell("mkdir -m 777 " + userMeasureDir);
			LogInfo("======userMeasurePath:"<<userMeasureDir<<" not exists, create it===");
		}
		
		Poco::File measureLnDir("/Measurement");
		if (measureLnDir.exists() == false)
		{
			ISFIT::Shell("ln -s " + userMeasureDir + "  /Measurement");
			LogInfo("======/Measurement not exists, create it====");
		}
		
		//软链接
		CData upgradeDir=userDataDir+"/upgrade";
		Poco::File upgradePath(upgradeDir.c_str());
		if (upgradePath.exists() == false)
		{
			ISFIT::Shell("mkdir -m 777 " + upgradeDir);
			LogInfo("======upgradePath:"<<upgradeDir<<" not exists, create it===");
		}
		
		Poco::File upgradeLnDir("/upgrade");
		if (upgradeLnDir.exists() == false)
		{
			ISFIT::Shell("ln -s " + upgradeDir + "  /upgrade");
			LogInfo("======/upgrade not exists, create it====");
		}

		param.push_back(std::make_tuple(CData(CMM::param::FsuId), CData("00-53-4C-00-01-44")));
		param.push_back(std::make_tuple(CData(CMM::param::UserName), CData("zhtest")));
		param.push_back(std::make_tuple(CData(CMM::param::Password), CData("mKnxGe@9g*%8")));
		param.push_back(std::make_tuple(CData(CMM::param::FtpUsr), CData("root")));
		param.push_back(std::make_tuple(CData(CMM::param::FtpPasswd), CData("aga2ForIot!")));
		param.push_back(std::make_tuple(CData(CMM::param::FSUPort), CData("8443")));
		param.push_back(std::make_tuple(CData(CMM::param::SCIp), CData("36.133.176.228")));
		param.push_back(std::make_tuple(CData(CMM::param::SCPort), CData("28006")));
		param.push_back(std::make_tuple(CData(CMM::param::SCIpRoute), CData("eth0")));
		param.push_back(std::make_tuple(CData(CMM::param::WebPort), CData("8080")));
		param.push_back(std::make_tuple(CData(CMM::param::SiteID), CData("5101072000001")));
		param.push_back(std::make_tuple(CData(CMM::param::SiteName), CData("川成都高升桥枢纽站")));
		param.push_back(std::make_tuple(CData(CMM::param::RoomID), CData("000000011")));
		param.push_back(std::make_tuple(CData(CMM::param::RoomName), CData("室内汇聚机房")));
		param.push_back(std::make_tuple(CData(CMM::param::GetMeasurementTime), CData("15")));
		param.push_back(std::make_tuple(CData(CMM::param::HeartBeatTimeout), CData("300")));
		param.push_back(std::make_tuple(CData(CMM::param::LoginTimeout), CData("60")));	
		param.push_back(std::make_tuple(CData(CMM::param::LoginState), CData("失败")));
		param.push_back(std::make_tuple(CData(CMM::param::LogFileSize), CData("1")));
		param.push_back(std::make_tuple(CData(CMM::param::LogLevel), CData("information")));
		param.push_back(std::make_tuple(CData(CMM::param::SoftVer), CData("4.5.0")));


		//m_datalog.AddStoreDataFunc();
		
		LogInfo("=====finish init module name:---------");
		
	}

	int CMMAccess::UpdateParam(std::map<CData, CData>& paramMap,std::map<CData,CData>& errorMap)
	{
		int ret =0;
		CData d1,d2,d3,c1,c2,c3, dc1,dc2,dc3;
		for (auto it=paramMap.begin(); it!=paramMap.end(); it++)
		{
			CData key = it->first;
			CData val = it->second;
			
			LogNotice("UpdateParam() key:"<<key<<" val:"<<val);

			if (key == CMM::param::FsuId)
			{
				CMMConfig::instance()->SetFsuId(val);
				//CMMConfig::instance()->SetParam(CMM::param::FsuId, val);
			}
			else if (key == CMM::param::UserName)
			{
				CMMConfig::instance()->SetUserName(val);
				//CMMConfig::instance()->SetParam(CMM::param::UserName, val);
			}
			else if (key ==CMM::param::Password)
			{
				CMMConfig::instance()->SetPassword(val);
				//CMMConfig::instance()->SetParam(CMM::param::Password, val);
			}
			else if (key == CMM::param::FtpUsr)
			{
				CMMConfig::instance()->SetFtpUsr(val);
			}
			else if (key ==CMM::param::FtpPasswd)
			{
				ret=CMMConfig::instance()->SetFtpPasswd(val);
				if(ret!=0)
				{
					LogInfo("SetFtpPasswd=== ret:"<<ret);
					ret = -100;
					errorMap[key] = "setftppwd_error";
				}
			}
			else if (key == CMM::param::FSUIp)
			{
				CMMConfig::instance()->SetFsuIp(val);
				//CMMConfig::instance()->SetParam(CMM::param::FSUIp, val);
			}
			else if (key == CMM::param::FSUPort)
			{
				CMMConfig::instance()->SetFsuPort(val);
				m_server->ListenPortChange(val.convertInt());
			}
			else if (key == CMM::param::WebPort)
			{
				m_webServer->ListenPortChange(val.convertInt());
			}
			else if (key == CMM::param::SCIp)
			{
				CData scIp = resolveDomainToIp(val.c_str());
				CMMConfig::instance()->m_scIp = scIp;
				//CMMConfig::instance()->SetParam(CMM::param::SCIp, val);
#ifdef ACCESSCONTROL
				CData scEndPoint = "udp://" + scIp + ":" + CMMConfig::instance()->m_scPort + "/v1/services/newLSCService";
#else // ACCESSCONTROL
				CData scEndPoint = "http://" + scIp + ":" + CMMConfig::instance()->m_scPort + "/v1/services/newLSCService";
#endif
				
				if (m_scEndPoint != scEndPoint)
				{
					m_scEndPoint = scEndPoint;
					m_registerStatus = CMM::CMM_REGISTER_FAILED; //sc地址如果发生变化 重新注册
					SetLoginState(false);
				}
			}
			else if (key == CMM::param::SCPort)
			{
				CMMConfig::instance()->m_scPort = val;
				//CMMConfig::instance()->SetParam(CMM::param::SCPort, val);
#ifdef ACCESSCONTROL
				CData scEndPoint = "udp://" + CMMConfig::instance()->m_scIp + ":" + val + "/v1/services/newLSCService";
#else // ACCESSCONTROL
				CData scEndPoint = "http://" + CMMConfig::instance()->m_scIp + ":" + val + "/v1/services/newLSCService";
#endif
				if (m_scEndPoint != scEndPoint)
				{
					m_scEndPoint = scEndPoint;
					m_registerStatus = CMM::CMM_REGISTER_FAILED; //sc地址如果发生变化 重新注册
					SetLoginState(false);
				}
			}
			else if (key == CMM::param::SCIpRoute)
			{
				CMMConfig::instance()->m_scIpRoute = val;
				//CMMConfig::instance()->SetParam(CMM::param::SCIpRoute, val);
			}
			
			else if (key==CMM::param::SiteID)
			{
				CMMConfig::instance()->m_SiteID = val;
			}		
			else if (key==CMM::param::SiteName)
			{
				CMMConfig::instance()->m_SiteName =val;
			}		
			else if (key==CMM::param::RoomID)
			{
				CMMConfig::instance()->m_RoomID = val;
			}		
			else if (key==CMM::param::RoomName)
			{
				CMMConfig::instance()->m_RoomName= val;
			}		
			
			else if (key == CMM::param::HeartBeatTimeout)
			{
				CMMConfig::instance()->m_heartbeatTimeout = val;
				//CMMConfig::instance()->SetParam(CMM::param::HeartBeatTimeout, val);
				m_heartBeatTime= val.convertInt();
			}	
			else if (key == CMM::param::LoginTimeout)
			{
				CMMConfig::instance()->m_loginTimeout = val;
				//CMMConfig::instance()->SetParam(CMM::param::LoginTimeout, val);
				m_registerTime = val.convertInt();
			}
		
			else if (key == CMM::param::LogFileSize)
			{
				
			}
			else if (key == CMM::param::LogLevel)
			{
				APPAPI::SetLogLevel(val);
			}
			else if (key == CMM::param::SoftVer)
			{
				CMMConfig::instance()->m_fsuVersion = val;
				//CMMConfig::instance()->SetParam(CMM::param::SoftVer, val);

			}
			else if (key == CMM::param::GetMeasurementTime)
			{
				CMMConfig::instance()->m_getMeasureMentTime = val;
				//CMMConfig::instance()->SetParam(CMM::param::GetMeasurementTime, val);
				m_wirteFileTime = val.convertInt();
			}
		}
		ReportDevConf();
	
		return ret;
	}
	

	void CMMAccess::start()
	{			
		LogInfo("======>CMMAccess start====>");
		if(m_bStart)
		{
			LogError("CMMAccess has started");
			return ;
		}
		m_bStart = true;
		Init();
		m_thread.start(*this);
		LogInfo("======>CMMAccess start ok====>");
	}

	void CMMAccess::stop()
	{	
		LogInfo("=== CMMAccess go to stop  ====");	
		m_bStart = false;
		DeInit();
		m_thread.join();
		SetLoginState(false);
		LogInfo("=== CMMAccess stop ok ====");	
	}
	
	void CMMAccess::DeInit()
	{
#ifdef ACCESSCONTROL
		m_udpServer->Stop();
#else // ACCESSCONTROL
		m_server->Stop();	
#endif
		m_webServer->Stop();
	}

	void CMMAccess::unInitialize()
	{
	}

	/*
	* 检查是否是白名单用户
	*/
	bool CMMAccess::checkIpAuth(const char* http_ip, int familyType)
	{
		CData strFamilyType;
		if (familyType == 2)
			strFamilyType = "IPV4";
		if (familyType == 23)
			strFamilyType = "IPV6";
		if (!CMMConfig::instance()->isAcceptIp(strFamilyType, http_ip))
		{
			LogNotice("client ip: " << http_ip << " is no access.");
			return false;
		}
		LogNotice("client ip: " << http_ip << " family type:" << strFamilyType.c_str());
		return true;
	}


	/*
	* 检查服务端token和计算的token是否一致
	*/
	bool CMMAccess::checkAuth(const char* http_auth_header, char* _xmlData)
	{
		LogInfo("recv checkAuth = " << http_auth_header << "\r\n");
		CData token,strToken;
		CData strOutMsg;
		CData strInMsg(_xmlData);
		UpdateAuthHeader(strInMsg,strOutMsg, token);

		std::stringstream ss(http_auth_header);
		std::string line, key, value;
		while (std::getline(ss, line, '\n'))
		{
			if (line.find("Authorization:") == 0)
			{
				Poco::RegularExpression regex(R"~(token="([^"]*)")~");
				Poco::RegularExpression::MatchVec matches;
				if (regex.match(line, 0, matches))
				{
					strToken = line.substr(matches[1].offset, matches[1].length);
				}
			}
		}

		LogInfo("recv token = " << strToken.c_str() << "\n calculate token = " << token.c_str());
		if (strToken.compare(token) != 0)
			return false;
		return true;
	}

	void CMMAccess::UpdateAuthHeader(const CData& message, CData& authHeader, CData& strtoken)
	{
		CData strUser = CMMConfig::instance()->m_userName;
		CData strPass = CMMConfig::instance()->GetPassword();
		//CData strVersion = CMMConfig::instance()->m_fsuVersion;
		CData strOutPass;
		//if (true == CTextEncryption::hashMessage(strPass, strOutPass, 1)) //sha256 散列passwd
		{
			//LogInfo("hashMessage passwd = " << strOutPass.c_str());
			strtoken = CTextEncryption::getToken(strPass, message);  //2. 原始passwd和 进行HMAC-SHA-256计算 再转成Base16
			authHeader = "appid=\"" + strUser + "\",token=\"" + strtoken + "\",v=\"4.5.0\"";
		}
	}

	CData CMMAccess::resolveDomainToIp(const char* domainName) 
	{
		LogInfo("resolveDomainToIp : " << domainName);
		if (strlen(domainName) < 1)
			return "";
		CData domainIp;
		struct addrinfo hints, * res, * p;
		int status;

		// 清空 hints 结构体
		memset(&hints, 0, sizeof(hints));

		// 设置 hints 参数
		hints.ai_family = AF_UNSPEC; // 可以是 IPv4 或 IPv6
		hints.ai_socktype = SOCK_STREAM; // 指定套接字类型，此处为流式套接字
		hints.ai_protocol = IPPROTO_TCP; // 可选，如果你关心协议的话

		// 执行域名解析
		if ((status = getaddrinfo(domainName, nullptr, &hints, &res)) != 0) 
		{
			LogInfo("getaddrinfo error: " << gai_strerror(status));
			return "";
		}

		// 遍历结果链表并打印IP地址
		for (p = res; p != nullptr; p = p->ai_next) 
		{
			char ipStringBuffer[INET_ADDRSTRLEN]; // 缓冲区足够容纳IPv4或IPv6地址
			void* addressPtr = nullptr;
			// 根据地址族选择适当的指针
			if (p->ai_family == AF_INET) 
			{
				sockaddr_in* ipv4 = reinterpret_cast<sockaddr_in*>(p->ai_addr);
				addressPtr = &(ipv4->sin_addr);
				inet_ntop(p->ai_family, addressPtr, ipStringBuffer, sizeof(ipStringBuffer));
				domainIp = ipStringBuffer;
				LogInfo("IP Address: " << ipStringBuffer);
				break;
			}
			/*else if (p->ai_family == AF_INET6) {
				sockaddr_in6* ipv6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
				addressPtr = &(ipv6->sin6_addr);
			}*/	
		}
		// 释放getaddrinfo返回的资源
		freeaddrinfo(res);
		return domainIp;
	}

}

