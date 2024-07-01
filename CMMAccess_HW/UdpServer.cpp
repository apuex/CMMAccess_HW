//canyon 2019 09 06

#include "UdpServer.h"
#include "Poco/Timespan.h"
#include "Poco/Exception.h"
#include "Poco/ErrorHandler.h"
#include "CMMProtocolEncode.h"
#include "CMMAccess.h"

using namespace Poco::Net;

#define MAX_RECEIVE_SIZE 65536

namespace CMM
{


	const unsigned int CMCC_MAX_RESPONSE_BUFFER_SIZE = 512 * 1024;

	CUdpServer::CUdpServer()
	{
		m_bStop = true;
		m_listenPort = -1;
	}


	CUdpServer::~CUdpServer()
	{
		Stop();
	}

	bool CUdpServer::ListenPortChange(int nPort)
	{
		if (m_listenPort != nPort)
		{
			m_listenPort = nPort;
			return true;
		}
		return false;
	}

	int CUdpServer::Start(int port)
	{
		if (port == -1)
		{
			LogError("cmm service endpoint an service port must be setted");
			return -1;
		}
		m_bStop = false;
		m_listenPort = port;
		m_thread.start(*this);
		return 0;
	}

	int CUdpServer::Stop()
	{
		if (m_bStop)
		{
			return -1;
		}
		// 等待线程结束（假设run方法会因m_bStop为true而退出循环）
		m_thread.join();
		
		m_ServerSocket.close();
		m_bStop = true;
		return 0;
	}

	void CUdpServer::run()
	{
		// 绑定端口并开始监听
		SocketAddress serverAddr(m_listenPort);
		m_ServerSocket.bind(serverAddr);
		LogInfo("udp server listen port : " << m_listenPort);
		while (m_bStop == false)
		{
			std::vector<char> buffer(MAX_RECEIVE_SIZE, 0); // 初始化为零的动态缓冲区
			SocketAddress senderAddr;
			int bytesReceived = m_ServerSocket.receiveFrom(buffer.data(), buffer.size(), senderAddr);
			if (bytesReceived < 0)
			{
				std::string response = "Error receiving data.";
				m_ServerSocket.sendTo(response.c_str(), response.length(), senderAddr);
				continue;
			}
			char msgBuf[CMCC_MAX_RESPONSE_BUFFER_SIZE] = {};
			int ret = CMMAccess::instance()->DoMsgProcess(buffer.data(), msgBuf, sizeof(msgBuf));
			if (ret < 0)
			{
				std::string response = "request data is not able to be parsed.";
				m_ServerSocket.sendTo(response.c_str(), response.length(), senderAddr);
				continue;
			}
			LogInfo("server send to client ip: "<< senderAddr.host() << " port : " <<senderAddr.port());
			m_ServerSocket.sendTo(msgBuf,strlen(msgBuf), senderAddr);
		}
		Stop();
	}
}






