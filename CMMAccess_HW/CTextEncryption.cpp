//canyon 2019 09 06

#include "CTextEncryption.h"
#include "CLog.h"
#include "openssl/sha.h"
//#include "openssl/openssl-1.1.1d/crypto/include/internal/sm3.h"
#include <string>
#include <sstream>
#include <iomanip>
#include "Poco/HMACEngine.h"
#include "openssl/aes.h"
#include "openssl/rand.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/hmac.h"  
#include "openssl/md5.h"

using namespace Poco::Net;

RSA* loadPublicKeyFromPEM(const CData& publicKeyPEM)
{
	BIO* bio = BIO_new_mem_buf(publicKeyPEM.c_str(), -1);
	if (!bio)
		throw std::runtime_error("Failed to create BIO");

	RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	if (!rsa)
	{
		BIO_free(bio);
		throw std::runtime_error("Failed to parse RSA public key");
	}

	BIO_free(bio);
	return rsa;
}

RSA* loadPrivateKeyFromPEM(const CData& privateKeyPEM)
{
	BIO* bio = BIO_new_mem_buf(privateKeyPEM.c_str(), -1);
	if (!bio)
		throw std::runtime_error("Failed to create BIO");

	RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if (!rsa)
	{
		BIO_free(bio);
		throw std::runtime_error("Failed to parse RSA public key");
	}

	BIO_free(bio);
	return rsa;
}

namespace CMM
{

	CTextEncryption::CTextEncryption()
	{
		
	}


	CTextEncryption::~CTextEncryption()
	{

	}

	
	bool CTextEncryption::hashMessage(const CData& inMessage, CData& outMessage,int nType)
	{
		// 创建一个stringstream用于构建十六进制字符串
		std::stringstream ss;
		if (nType == 0)  //MD5
		{
			Poco::MD5Engine md5;
			md5.update(inMessage.c_str(), inMessage.length());
			outMessage = Poco::DigestEngine::digestToHex(md5.digest()).c_str();
		}
		else if (nType == 1) // SHA - 256(appkey)
		{
			unsigned char hash[SHA256_DIGEST_LENGTH];
			SHA256_CTX sha256;
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, inMessage.c_str(), inMessage.length());
			SHA256_Final(hash, &sha256);
			for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i] & 0xff);
			}
			std::string token = ss.str();
			std::string outToken;
			for (char& c : token)
			{
				if (c >= 'a' && c <= 'f') {
					c = c - 'a' + 'A';
				}
				outToken += c;
			}
			outMessage = outToken;
		}
		else if (nType == 2)  //SM3
		{
			// 初始化原始数据缓冲区和SM3上下文
			//unsigned char hash[SM3_DIGEST_LENGTH];
			//SM3_CTX sm3;
			//// 初始化并更新SM3上下文
			//sm3_init(&sm3);
			//sm3_update(&sm3, passwd.c_str(), passwd.length());
			//// 生成SM3散列值
			//sm3_final(hash, &sm3);
			//// 将二进制散列值转换为大写的十六进制字符串
			//for (int i = 0; i < SM3_DIGEST_LENGTH; ++i) {
			//	ss << std::hex << std::uppercase << static_cast<int>(hash[i]);
			//}
			return false;
		}
		else
		{
			return false;
		}
		return true;
	}

	CData CTextEncryption::getToken(const CData& appKey, const CData& body)
	{
		unsigned char md5_digest[MD5_DIGEST_LENGTH];
		MD5((unsigned char*)body.c_str(), body.size(), md5_digest);

		unsigned char hmac_digest[EVP_MAX_MD_SIZE];
		unsigned int hmac_len;

		HMAC_CTX* hmac_ctx = HMAC_CTX_new();
		HMAC_Init_ex(hmac_ctx, appKey.c_str(), appKey.size(), EVP_sha256(), NULL);
		HMAC_Update(hmac_ctx, (unsigned char*)md5_digest, sizeof(md5_digest));
		HMAC_Final(hmac_ctx, hmac_digest, &hmac_len);
		HMAC_CTX_free(hmac_ctx);

		std::stringstream ss;
		for (unsigned int i = 0; i < hmac_len; ++i) {
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hmac_digest[i] & 0xff);
		}

		std::string hexString = ss.str();
		std::string outString;
		for (char& c : hexString) 
		{
			if (c >= 'a' && c <= 'f') 
			{
				c = c - 'a' + 'A';
			}
			outString += c;
		}
		return outString;
	}


}

