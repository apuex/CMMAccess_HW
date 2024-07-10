//canyon 2019 09 06

#include "UdpClient.h"
#include "TransData.h"
#include "CLog.h"
#include "openssl/sha.h"
//#include "openssl/openssl-1.1.1d/crypto/include/internal/sm3.h"
#include <string>
#include <sstream>
#include <iomanip>
#include "Poco/HMACEngine.h"
#include "Poco/StreamCopier.h"

using namespace Poco::Net;



namespace CMM
{





	CUdpClient::CUdpClient()
	{

	}

	CUdpClient::~CUdpClient()
	{

	}

	void CUdpClient::Start()
	{
		//m_pUser = url;
	}

	int CUdpClient::SendXmlData(const char* url, CData xmlData, CData& recvData)
	{
		Poco::URI uri(url);
		std::string serverAddress = uri.getHost();
		int serverPort = uri.getPort();
		LogInfo("SEND data to serverAddress "<< serverAddress << " and serverPort:"<< serverPort);
		try
		{
			DatagramSocket socket;

			SocketAddress serverAddr(SocketAddress::IPv4, serverAddress, serverPort);

			std::vector<uint8_t> sendData = CTransData::PackageSendData(xmlData);
			int sentBytes = socket.sendTo(sendData.data(), sendData.size(), serverAddr);
			if (sentBytes < 0)
			{
				LogError("send msg error: " << sentBytes);
				return -1;
			}
			// �������ݣ����Լ��ش��߼�
			bool received = false;
			int recvBytes = 0;
			int nCount = 0;
			std::vector<uint8_t> recvBuffer; // ��ʼ��СΪ1024  
			recvBuffer.resize(1024);
			while (true) 
			{
				SocketAddress senderAddr;
				recvBytes = socket.receiveFrom(recvBuffer.data(), recvBuffer.size(), senderAddr);
				if (recvBytes <= 0)
				{	
					nCount++;
				}
				else if (nCount > 3)
				{
					received = false;
					LogError("recv ip: " << senderAddr.host() << " data recv error. please check data retry.");
					break;
				}
				else if (recvBytes == (int)recvBuffer.size()) 
				{
					// ���������ܲ����������������ݣ����ӻ�������С  
					recvBuffer.resize(recvBuffer.size() * 2); // ʾ�����ӱ���������С  
				}
				else if (recvBuffer.size() >= MAX_RECV_DATASIZE)
				{
					received = false;
					LogError("recv ip: "<< senderAddr.host()<<" data is so Larger. please check data retry.");
					break;
				}
				else 
				{
					received = true;
					break; // �յ�С�ڻ�������С�����ݣ���������  
				}
			}
			if (!received)
			{
				LogError("Failed to receive data after retries.");
				return -2;
			}
			std::string strRecv;
			if (!CTransData::UnPackageRecvData(recvBuffer, recvBytes, strRecv))
			{
				LogError("Failed to :UnPackageRecvData.");
				return -3;
			}
			recvData = strRecv.c_str();
			socket.close();
		}
		catch (Poco::Exception& exc)
		{
			LogError("Exception msg: " << exc.displayText());
			return -4;
		}
		return 0;
	}

	int CUdpClient::SendHeart(const char* url)
	{
		Poco::URI uri(url);
		std::string serverAddress = uri.getHost();
		int serverPort = uri.getPort();
		try
		{
			DatagramSocket socket;

			SocketAddress serverAddr(SocketAddress::IPv4, serverAddress, serverPort);

			std::vector<uint8_t> sendData = CTransData::PackageSendHeart();
			int sentBytes = socket.sendTo(sendData.data(), sendData.size(), serverAddr);
			if (sentBytes < 0)
			{
				LogError("send msg error: " << sentBytes);
				return -1;
			}
			socket.close();
		}
		catch (Poco::Exception& exc)
		{
			LogError("Exception msg: " << exc.displayText());
			return -4;
		}
		return 0;
	}
}

