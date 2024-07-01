//canyon 2019 09 06

#include "UdpClient.h"
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

			int sentBytes = socket.sendTo(xmlData.c_str(), static_cast<int>(xmlData.size()), serverAddr);
			if (sentBytes < 0)
			{
				LogError("send msg error: " << sentBytes);
				return -1;
			}
			// �������ݣ����Լ��ش��߼�
			bool received = false;
			for (int attempt = 0; attempt < 3 && !received; ++attempt)
			{
				char recvBuffer[1024];
				SocketAddress senderAddr;
				socket.setReceiveTimeout(Poco::Timespan(0, 0, 0, 2, 0)); // ���ý��ճ�ʱ  
				int recvBytes = socket.receiveFrom(recvBuffer, sizeof(recvBuffer), senderAddr);
				if(recvBytes > 0)
				{
					responseData.assign(recvBuffer, recvBytes);
					received = true;
				}
				else
				{
					// ���ճ�ʱ�������������  
					LogError("recv msg error: " << recvBytes);
				}
			}

			if (!received)
			{
				LogError("Failed to receive data after retries.");
				return -2;
			}
			socket.close();
		}
		catch (Poco::Exception& exc)
		{
			LogError("Exception msg: " << exc.displayText());
			return -3;
		}
		return 0;
	}

}

