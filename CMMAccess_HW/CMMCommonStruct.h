#ifndef _CMMCOMMONSTRUCT_H
#define _CMMCOMMONSTRUCT_H
#include "Data.h"
#include "list"
#include "Poco/Timestamp.h"
#define CMM_ID_LENGTH			12
#define CMM_NAME_LENGTH			80
#define CMM_DES_LENGTH			40
#define CMM_NMALARMID_LEN		40
#define CMM_DEVICEID_LEN		26
#define CMM_VER_LENGTH			20
#define CMM_TIME_LEN			19

	//01~09  11~18 20,68,76,77,78,87,88,92,93,95
	/*
#define Is_range(iID) (iID>=1&&iID<=9)||(iID>=11&&iID<=20)||iID==68||(iID>=76&&iID<=78) ||(iID>=87&&iID<=88) ||(iID>=92&&iID<=93)||(iID==95)
#define Is_rangeData(iID) (iID>=1&&iID<=9)||(iID>=11&&iID<=18)||iID==68||(iID>=76&&iID<=78) ||(iID>=87&&iID<=88) ||(iID>=92&&iID<=93)||(iID==95)
#define Is_rangeThreshold(iID) (iID>=1&&iID<=9)||(iID>=11&&iID<=20)||iID==68||(iID>=76&&iID<=78) ||(iID>=87&&iID<=88) ||(iID>=92&&iID<=93)*/

#define Is_range(iID) ((iID>=1&&iID<=9)||(iID>=11&&iID<=18)||iID==68||(iID>=76&&iID<=78) ||(iID>=87&&iID<=88) ||(iID>=92 && iID<=96))
#define Is_rangeData(iID) Is_range(iID)
#define Is_rangeThreshold(iID) (iID==20) //Is_range(iID)
#define Is_rangeAlarm(iID) ((iID>=1&&iID<=10)||(iID>=11&&iID<=20)||iID==68||(iID>=76&&iID<=78) ||(iID>=87&&iID<=88) ||(iID>=92&&iID<=93)||(iID==95))

namespace CMM{
	namespace param{
		const char* const SiteID = "站点编号";
		const char* const SiteName = "站点名称";
		const char* const RoomID = "机房编号";
		const char* const RoomName = "机房名称";
		const char* const xx = "经度";
		const char* const yy = "纬度";
		
		
		const char* const DeviceIdList = "设备ID列表";
		const char* const BrandModelList = "品牌型号列表";
		const char* const DeviceDescList = "设备描述列表";
		const char* const DeviceCapList = "额定容量列表";
		const char* const DeviceVersionList = "设备版本列表";
		const char* const DeviceTimeList = "启用时间列表";

		const char* const FsuId  = "设备ID";
	//	const char* const FsuCode  = "设备Code";
		const char* const UserName = "设备账号";
		const char* const Password = "设备密码";
		const char* const AlgType = "散列算法";
		const char* const FtpUsr = "FTP账号";
		const char* const FtpPasswd = "FTP密码";
		const char* const FtpUserName = "FTP账号";
		const char* const FtpPassword = "FTP密码";
		const char* const DeviceListJson = "设备列表Json";
		const char* const IgnoreAlarmLevel = "过滤告警级别(如2,3)";
		const char* const HeartBeatTimeout = "心跳超时（秒）";
		const char* const LoginTimeout = "注册超时（秒）";
		const char* const GetMeasurementTime= "监控数据文件（分）";
		const char* const SCEndPoint = "CMM.SCEndPoint";
		const char* const FSUEndPoint = "CMM.FSUEndPoint";
		const char* const SCIp = "平台IP";
		const char* const SCDomain = "平台域名";
		const char* const SCPort = "平台端口";
		const char* const SCIpRoute = "平台路由";
		const char* const FSUIp = "设备IP";
		const char* const FSUPort = "设备端口";
		const char* const DevCfgTime = "设备配置时间";
		const char* const LoginState = "注册状态";
		const char* const LoginFailTime = "注册失败（小时）";
		const char* const LogFileSize = "日志大小(Mb)";
		const char* const LogLevel = "日志级别";
		const char* const SoftVer = "软件版本";
	}
const char* const Request = "Request";
const char* const Response = "Response";
const char* const PK_Type = "PK_Type";
const char* const Name = "Name";
const char* const Info = "Info";
const char* const UserName = "UserName";
const char* const PassWord = "PassWord";
const char* const AlgType = "AlgType";
const char* const FSUID = "FSUID";
const char* const FSUIP = "FSUIP";
const char* const FSUMAC = "FSUMAC";
const char* const FSUVER = "FSUVER";
const char* const RightLevel = "RightLevel";
const char* const Values = "Values";
const char* const DeviceList = "DeviceList";
const char* const Device = "Device";
const char* const ID = "ID";
const char* const TDevConfdesc = "TDevConfdesc";
const char* const Time = "Time";

namespace method{
	const char* const LOGIN = "LOGIN";
	const char* const LOGIN_ACK = "LOGIN_ACK";
	const char* const SEND_DEV_CONF_DATA = "SEND_DEV_CONF_DATA";
	const char* const SEND_DEV_CONF_DATA_ACK = "SEND_DEV_CONF_DATA_ACK";
	const char* const GET_DEV_CONF = "GET_DEV_CONF";
	const char* const GET_DEV_CONF_ACK = "GET_DEV_CONF_ACK";
	const char* const SET_DEV_CONF_DATA = "SET_DEV_CONF_DATA";
	const char* const SET_DEV_CONF_DATA_ACK = "SET_DEV_CONF_DATA_ACK";
	const char* const GET_FSUINFO = "GET_FSUINFO";
	const char* const GET_FSUINFO_ACK = "GET_FSUINFO_ACK";
	const char* const GET_DATA = "GET_DATA";
	const char* const GET_DATA_ACK = "GET_DATA_ACK";
	const char* const TIME_CHECK = "TIME_CHECK";
	const char* const TIME_CHECK_ACK = "TIME_CHECK_ACK";
	const char* const SEND_ALARM = "SEND_ALARM";
	const char* const SEND_ALARM_ACK = "SEND_ALARM_ACK";
	const char* const SET_POINT = "SET_POINT";
	const char* const SET_POINT_ACK = "SET_POINT_ACK";
	const char* const GET_THRESHOLD = "GET_THRESHOLD";
	const char* const GET_THRESHOLD_ACK = "GET_THRESHOLD_ACK";
	const char* const SET_THRESHOLD = "SET_THRESHOLD";
	const char* const SET_THRESHOLD_ACK = "SET_THRESHOLD_ACK";
	const char* const SEND_DATA = "SEND_DATA";
	const char* const SEND_DATA_ACK = "SEND_DATA_ACK";
	const char* const GET_FTP ="GET_FTP";
	const char* const GET_FTP_ACK = "GET_FTP_ACK";
	const char* const SET_FTP = "SET_FTP";
	const char* const SET_FTP_ACK = "SET_FTP_ACK";
	const char* const SET_LOGININFO = "SET_LOGININFO";
	const char* const SET_LOGININFO_ACK = "SET_LOGININFO_ACK";
	const char* const GET_LOGININFO = "GET_LOGININFO";
	const char* const GET_LOGININFO_ACK = "GET_LOGININFO_ACK";
	const char* const UPDATE_FSUINFO_INTERVAL = "UPDATE_FSUINFO_INTERVAL";
	const char* const UPDATE_FSUINFO_INTERVAL_ACK = "UPDATE_FSUINFO_INTERVAL_ACK";
	//canyon
	const char* const GET_STORAGERULE = "GET_STORAGERULE";
	const char* const GET_STORAGERULE_ACK = "GET_STORAGERULE_ACK";
	const char* const SET_STORAGERULE = "SET_STORAGERULE";
	const char* const SET_STORAGERULE_ACK = "SET_STORAGERULE_ACK";

	//NEW 
	const char* const GET_TIME = "GET_TIME";
	const char* const GET_TIME_ACK = "GET_TIME_ACK";
	const char* const SET_ACCEPT_IP_CONF = "SET_ACCEPT_IP_CONF";
	const char* const SET_ACCEPT_IP_CONF_ACK = "SET_ACCEPT_IP_CONF_ACK";
	const char* const SET_FSUREBOOT = "SET_FSUREBOOT";
	const char* const SET_FSUREBOOT_ACK = "SET_FSUREBOOT_ACK";
}

enum EnumResult
{
	FAILURE = 0,
	SUCCESS = 1,
	ILLEGALACCESS = 2,
	AUTHERROR = 3,
	NODATA = 4,
	UNCONFIG = 5,
	UNLOGIN = 6,
};

enum EnumRightMode
{
	INVALID = 0,
	LEVEL1 = 1,
	LEVEL2 = 2,
};
enum EnumType
{
	DI = 4,  //数字输入 遥信
	AI = 3,  //模拟输入 遥测
	DO = 1,  //数字输出 遥控
	AO = 2,  //模拟输出 遥调
	ALARM = 0,  //告警
};

enum EnumState
{
	STATE_NOALARM = 0,
	STATE_INVALID = 1,
};

enum EnumFlag
{
	BEGIN,
	END,
};

typedef struct  	sTSignal
{
	public:
		sTSignal()
		{
			Type = -1; AlarmLevel=-1; savePeriod = -1; SignalNumber = 0;
			Threshold=0.001; AbsoluteVal=0.001; RelativeVal=0.001; SetupVal = 0.001; 
		}
	int Type;
	CData ID;
	CData SignalName;
	int AlarmLevel;
	float Threshold;
	float AbsoluteVal;
	float RelativeVal;
	int savePeriod; //canyon
	CData Describe;
	CData NMAlarmID;
	int SignalNumber;
	float SetupVal;
	int result;
}TSignal;

typedef struct		  sTDevConf
{
	CData DeviceID;
	CData DeviceName;
	CData RoomName;
	CData SiteName;
	CData RoomID;
	CData SiteID;
	int DeviceType;
	int DeviceSubType;
	CData Model;
	CData Brand;
	float RatedCapacity;
	CData Version;
	CData BeginRunTime;
	CData DevDescribe;
	CData ConfRemark;
	std::list<TSignal> singals;
	int result;
}TDevConf;

typedef struct  
{
	int Type;
	CData ID;
	float MeasuredVal;
	float SetupVal;
	int Status;
	CData Time;
	int SignalNumber;
	int result;
	int AlarmLevel; //写性能文件判定条件 xml不需要该参数
}TSemaphore;

typedef struct
{
	int Years;
	int Month;
	int Day;
	int Hour;
	int Minute;
	int Second;
}TTime;

typedef struct  
{
	CData SerialNo;
	CData ID;
	CData DeviceID;
	CData NMAlarmID;
	CData AlarmTime;
	int AlarmLevel;
	CData AlarmFlag;
	CData AlarmDesc;
	float EventValue;
	CData AlarmRemark1;
	CData AlarmRemark2;
	int SignalNumber;
	int retryTimes;
	Poco::Timestamp lastReportTime;
}TAlarm;

typedef struct
{
	int Type;
	CData ID;
	CData NMAlarmID;
	float Threshold;
	float AbsoluteVal;
	float RelativeVal;
	int AlarmLevel;
	int Status;
	int SignalNumber;
	int result;
}TThreshold;

typedef struct
{
	CData Status;
	CData lastHeartBeatTime;
	int RightLevel;
}TServerStatus;

typedef struct
{
	CData DeviceNo;   //设备编码
	CData DeviceName; //设备名称
	CData DeviceSubType;//设备子类型
	CData Brand;//设备品牌
	CData Model;//设备型号
	CData Desc;//描述
	CData RatedCapacity;//额定容量
	CData Version;//版本
	CData BeginRunTime;//启用时间
}TDeviceInfo;
}
#endif
