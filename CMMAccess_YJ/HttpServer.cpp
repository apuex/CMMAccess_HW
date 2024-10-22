//canyon 2019 09 06

#include "HttpServer.h"
#include "Poco/Timespan.h"
#include "Poco/Exception.h"
#include "Poco/ErrorHandler.h"
#include "CMMProtocolEncode.h"
#include "CMMAccess.h"

using namespace Poco::Net;



namespace CMM
{


	const unsigned int CMCC_MAX_RESPONSE_BUFFER_SIZE = 512 * 1024;

	CHTTPRequestHandlerFactory::CHTTPRequestHandlerFactory()
	{

	}


	CHTTPRequestHandlerFactory::~CHTTPRequestHandlerFactory()
	{
	}

	CHTTPRequestHandler* CHTTPRequestHandlerFactory::createRequestHandler(const HTTPServerRequest& request)
	{

		CHTTPRequestHandler* pRequestHandler = new CHTTPRequestHandler(this);
		{
			Poco::FastMutex::ScopedLock lock(m_connectionMapMutex);
			SocketAddress clientAddr = request.clientAddress();
			CData key = CData(clientAddr.host().toString()) + ":" + CData(clientAddr.port());
			m_HttpRequestHandlerMap[key] = pRequestHandler;
		}

		return pRequestHandler;
	}

	HTTPRequestHandler* CHTTPRequestHandlerFactory::GetHttpServerConnection(CData key)
	{
		Poco::FastMutex::ScopedLock lock(m_connectionMapMutex);
		auto it = m_HttpRequestHandlerMap.find(key);
		if (it != m_HttpRequestHandlerMap.end())
		{
			return it->second;
		}
		return nullptr;
	}


	void CHTTPRequestHandlerFactory::DelHttpServerConnection(CData key)
	{
		Poco::FastMutex::ScopedLock lock(m_connectionMapMutex);
		auto it = m_HttpRequestHandlerMap.find(key);
		if (it != m_HttpRequestHandlerMap.end())
		{
			m_HttpRequestHandlerMap.erase(it);
		}

	}


	CHTTPRequestHandler::CHTTPRequestHandler(void* owner)
	{
		m_owner = owner;
	}

	CHTTPRequestHandler::~CHTTPRequestHandler()
	{


	}

	//从http请求获取认证信息 再解析出token值
	std::string extractTokenFromCustomAuth(const std::string& customAuth) {
		std::istringstream iss(customAuth);
		std::string token;
		std::string field;
		std::map<std::string, std::string> fields;
		while (std::getline(iss, field, ',')) 
		{
			std::size_t eqPos = field.find('=');
			if (eqPos != std::string::npos) {
				std::string key = field.substr(0, eqPos);
				std::string value = field.substr(eqPos + 1, field.size() - eqPos - 1); // 去掉等于号和两边的引号
				if (key == "token") {
					token = value;
					break;
				}
				fields[key] = value;
			}
		}

		return token;
	}

	void CHTTPRequestHandler::handleRequest(HTTPServerRequest& request, HTTPServerResponse& response)
	{
		
		CData requestUri = request.getURI();
		CData method = request.getMethod().c_str();
		LogInfo("method : "<< method);
		if (method == "GET")
		{
			// 设置响应状态码和头部  
			response.setStatusAndReason(HTTPResponse::HTTP_NOT_FOUND);
			response.setContentType("application/xml; charset=UTF-8");
			response.send();
			return;
		}
		else if (method == "POST")
		{
			Poco::URI uri(requestUri.c_str());
			CData path = uri.getPath();
			if (path != "/v1/services/newFSUService" && path != "/services/FSUService")
			{
				response.setStatusAndReason(HTTPResponse::HTTP_NOT_FOUND);
				response.setContentType("application/xml; charset=UTF-8");
				std::ostream& out = response.send();
				out << "404 page not found";
				return;
			}
			/*bool bstate = CMMAccess::instance()->m_bLoginOK;
			if (!bstate)
			{
				response.setStatusAndReason(HTTPResponse::HTTP_BAD_REQUEST);
				response.setContentType("application/xml; charset=UTF-8");
				std::ostream& out = response.send();
				out << "Device not registered or registration expired";
				return;
			}*/
			if (request.getContentLength() == 0)
			{
				response.setStatusAndReason(HTTPResponse::HTTP_BAD_REQUEST);
				response.setContentType("application/xml; charset=UTF-8");
				std::ostream& out = response.send();
				out << "Bad Request";
				return;
			}
			static char msgBuf[CMCC_MAX_RESPONSE_BUFFER_SIZE];
			//解析请求体
			std::string requestBody;
			try
			{
				// 直接读取整个响应体到字符串
				std::istream& rs = request.stream();
				requestBody.resize(static_cast<std::size_t>(request.getContentLength()));
				rs.read(&requestBody[0], requestBody.size());

				// 如果实际读取的字节数小于请求头中的Content-Length，说明可能读取不完整
				if (rs.gcount() != static_cast<std::streamsize>(requestBody.size()))
				{
					// 处理读取不完整的情况...
					response.setStatusAndReason(HTTPResponse::HTTP_BAD_REQUEST);
					response.setContentType("application/xml; charset=UTF-8");
					std::ostream& out = response.send();
					out << "Read xmlData Incomplete reading.";
					return;
				}
				else
				{
					// 现在responseBody包含了整个XML内容，可以进行后续处理
					CData xmlData, auth_header, token;
					xmlData = requestBody;
					CMMAccess::instance()->UpdateAuthHeader(xmlData, auth_header, token);
					std::string strAuth = request.get("Authorization");
					CData requestToken = extractTokenFromCustomAuth(strAuth);
					//LogInfo("recv Authorization:" << strAuth.c_str());
					//LogInfo("recv Auth token:" << requestToken.c_str() << " and Calculate the token:" << token.c_str());
					//if (requestToken != token)
					//{
					//	memset(msgBuf, 0, strlen(msgBuf));
					//	CMMAccess::instance()->DoMsgProcess_Error((char*)requestBody.c_str(), msgBuf, (int)CMCC_MAX_RESPONSE_BUFFER_SIZE);
					//	response.setStatusAndReason(HTTPResponse::HTTP_OK);
					//	response.setContentType("application/xml; charset=UTF-8");
					//	std::ostream& out = response.send();
					//	out.write(msgBuf, strlen(msgBuf)); // 直接使用write方法发送缓冲区内容，避免字符串拷贝
					//	return;
					//}
				}
			}
			catch (Poco::Exception& e)
			{
				// 处理异常情况
				response.setStatusAndReason(HTTPResponse::HTTP_BAD_REQUEST);
				response.setContentType("application/xml; charset=UTF-8");
				std::ostream& out = response.send();
				out << "Bad Request";
				return;
			}
			try
			{
				memset(msgBuf, 0, strlen(msgBuf));
				int ret = CMMAccess::instance()->DoMsgProcess((char*)requestBody.c_str(), msgBuf, (int)CMCC_MAX_RESPONSE_BUFFER_SIZE);
				if (ret < 0)
				{
					response.setStatusAndReason(HTTPResponse::HTTP_OK);
					response.setContentType("application/xml; charset=UTF-8");
					std::ostream& out = response.send();
					out << "request data is not able to be parsed.";
					return;
				}
				response.setStatusAndReason(HTTPResponse::HTTP_OK);
				response.setContentType("application/xml; charset=UTF-8");
				std::ostream& out = response.send();
				out.write(msgBuf, strlen(msgBuf));
			}
			catch (Poco::Exception& e)
			{
				LogError("handleRequest caught an exception: name:" << e.name() << ", what:" << e.what() << ", text:" << e.displayText());
				// 异常情况下，发送一个通用的错误响应
				response.setStatusAndReason(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
				response.setContentType("application/xml; charset=UTF-8");
				std::ostream& out = response.send();
				out << "internal server error";
			}
			catch (...)
			{
				LogError("handleRequest caught an unknown exception.");
				// 未知异常，发送一个通用的错误响应
				response.setStatusAndReason(HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
				response.setContentType("application/xml; charset=UTF-8");
				std::ostream& out = response.send();
				out << "Unknown error occurred";
			}
		}
		else
		{
			response.setStatusAndReason(HTTPResponse::HTTP_NOT_FOUND);
			response.setContentType("application/xml; charset=UTF-8");
			response.send();
		}

		// 检查响应是否成功发送  
		if (response.sent())
		{
			LogNotice("Response send successfully.");
		}	
		else
		{
			LogNotice("Failed to send response.");
			CHttpServer::DisConnection();
		}
	}

	bool CHttpServer::m_bConnection = true;

	CHttpServer::CHttpServer()
	{
		m_bStop = true;
		m_listenPort = -1;
		m_pHttpServer = nullptr;
	}


	CHttpServer::~CHttpServer()
	{
		Stop();
	}

	bool CHttpServer::ListenPortChange(int nPort)
	{
		if (m_listenPort != nPort)
		{
			m_listenPort = nPort;
			m_bConnection = false;
			return true;
		}
		return false;
	}

	int CHttpServer::Start(int port, CData endpoint)
	{
		if (port == -1 || endpoint.empty())
		{
			LogError("cmm service endpoint an service port must be setted");
			return -1;
		}
		if (m_bStop == false)
		{
			LogError("cmm server has start");
			return -1;
		}
		m_bStop = false;
		m_listenPort = port;
		m_pParam = new HTTPServerParams();
		m_pFactory = new CHTTPRequestHandlerFactory();
		m_thread.start(*this);
		return 0;
	}

	void CHttpServer::DeleteConnection(CData clientIp, int port)
	{
		CData key = clientIp;
		key += ":";
		key += CData(port);
		m_pFactory->DelHttpServerConnection(key);
	}

	int CHttpServer::Stop()
	{
		if (m_bStop)
		{
			return -1;
		}
		m_bStop = true;
		// 停止HTTP服务器
		if (m_pHttpServer)
		{
			m_pHttpServer->stop();
		}
		// 等待线程结束（假设run方法会因m_bStop为true而退出循环）
		m_thread.join();
		// 清理资源
		if (m_pHttpServer)
		{
			delete m_pHttpServer;
			m_pHttpServer = nullptr;
		}
		m_ServerSocket.close();
		m_bConnection = true;
		m_bStop = true;
		return 0;
	}

	void CHttpServer::run()
	{
		// 绑定端口并开始监听
		m_ServerSocket = ServerSocket(m_listenPort);
		m_ServerSocket.listen();
		m_pHttpServer = new HTTPServer(m_pFactory, m_ServerSocket, m_pParam);
		m_pHttpServer->start();
		while (m_bStop == false)
		{
			if (!m_bConnection)
			{
				try
				{
					if (m_pHttpServer)
					{
						m_pHttpServer->stop();
						delete m_pHttpServer;
						m_pHttpServer = nullptr;
						
					}
					// 绑定端口并开始监听
					m_ServerSocket.close();
					LogInfo("serverSocket listen port:" << m_listenPort);
					m_ServerSocket = ServerSocket(m_listenPort);
					m_ServerSocket.listen();
					m_pHttpServer = new HTTPServer(m_pFactory, m_ServerSocket, m_pParam);
					m_pHttpServer->start();
					m_bConnection = true;
					
				}
				catch (const Poco::Exception& e)
				{
					LogError("Server exception: " << e.displayText());
					m_bConnection = false;
					if (m_pHttpServer != nullptr) // 检查是否为nullptr以避免双重删除  
					{
						m_pHttpServer->stop();
						delete m_pHttpServer;
						m_pHttpServer = nullptr;
						m_ServerSocket.close();
					}
				}
			}
			else if (m_bStop)
			{
				break;
			}
			Poco::Thread::sleep(1000);
		}
		Stop();
	}

	void CHttpServer::DisConnection()
	{
		m_bConnection = false;
	}
}






