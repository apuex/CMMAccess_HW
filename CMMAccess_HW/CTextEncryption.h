//canyon 2019 09 06

#pragma once

#include <stdio.h>
#include "Data.h"
#include "Poco/Net/SSLManager.h"
#include "Poco/DigestStream.h"
#include "Poco/MD5Engine.h"
#include "openssl/rand.h"

using namespace Poco::Net;


namespace CMM
{

class CTextEncryption
{

	public:
		CTextEncryption();
		~CTextEncryption();

		/*
		*getToken(message, outMessage)
		* appKey appkey 散列后密码
		* body:HTTP消息体
		* reuturn 转出串 token值
		*/
		static CData getToken(const CData& appKey, const CData& body);

		/*
		* md5(inMessage, outMessage,nType)
		* inMessage http消息体
		* outMessage http消息体转出串
		* nType:    转出串算法 0md5 1 SHA256 2 sm3...
		*/
		static bool hashMessage(const CData& inMessage, CData& outMessage, int nType);

};

}


