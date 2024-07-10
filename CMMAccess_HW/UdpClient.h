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
		* ����xml���� ����1�ɹ� -2��ʱ ����ʧ��
		*/
		int SendXmlData(const char* url, CData xmlData, CData& recvData);
		/*
		* ��������
		*/
		int SendHeart(const char* url);
	private:
		std::string m_pUser;
	};
		
}
