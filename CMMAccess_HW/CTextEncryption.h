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
		* appKey appkey ɢ�к�����
		* body:HTTP��Ϣ��
		* reuturn ת���� tokenֵ
		*/
		static CData getToken(const CData& appKey, const CData& body);

		/*
		* md5(inMessage, outMessage,nType)
		* inMessage http��Ϣ��
		* outMessage http��Ϣ��ת����
		* nType:    ת�����㷨 0md5 1 SHA256 2 sm3...
		*/
		static bool hashMessage(const CData& inMessage, CData& outMessage, int nType);

};

}


