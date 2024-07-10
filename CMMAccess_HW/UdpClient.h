//canyon 2019 09 06

#pragma once

#include <stdio.h>
#include "Poco/SharedPtr.h"
#include "Poco/DateTimeFormatter.h"
#include "Poco/DateTimeFormat.h"
#include "Poco/Timestamp.h"
#include "Data.h"


#include "Poco/Net/DatagramSocket.h"
#include "Poco/Net/SocketAddress.h" 
#include "Poco/Net/SocketAddressImpl.h"
#include "Poco/URI.h"
#include "Poco/DigestStream.h"

using namespace Poco::Net;


namespace CMM
{

	class CUdpClient 
	{

	public:
		CUdpClient();
		~CUdpClient();
		void Start();
		/*
		* 发送xml数据 返回1成功 -2超时 其他失败
		*/
		int SendXmlData(const char* url, CData xmlData, CData& recvData);
		/*
		* 发送心跳
		*/
		int SendHeart(const char* url);
	private:
		std::string m_pUser;
	};
		
}
