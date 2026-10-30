#pragma once

#include "utils.h"
#include "TLSHeaders.h"
#include <cstdlib>

class TLSHandshake {
private:
	unsigned char type;
	unsigned int length; // ONLY THE LAST 3 BYTES!
	unsigned short version;
	unsigned char random[32];

	unsigned char sessionIdLength;
	unsigned char sessionId[32];

	unsigned short cipherSuitesLength;
	std::vector<unsigned short> cipherSuites;

	unsigned char compressionMethodLength;
	std::vector<unsigned char> compressionMethods;

	unsigned short extensionsLength;
	std::vector<TLSExtension> extensions;

	unsigned long payloadLength;
	unsigned char* payload;

	unsigned long parseClientKeyExchange(unsigned char payload[]) {
		payloadLength = length;
		if (payloadLength > 0) setPayload(payload + 4, payloadLength);
		return payloadLength + 4;
	}

	unsigned long parseClientHello(unsigned char payload[], unsigned long counter) {

		unsigned long ctr = counter;

		version = (payload[4] << 8) + payload[5];
		memcpy(random, payload + 6, 32);

		sessionIdLength = payload[ctr++];
		memcpy(sessionId, payload + ctr, sessionIdLength);
		ctr += sessionIdLength;

		cipherSuitesLength = payload[ctr++] << 8;
		cipherSuitesLength += payload[ctr++];

		cipherSuites.reserve(cipherSuitesLength);
		for (int i = 0; i < cipherSuitesLength; i += 2) {
			unsigned short suite = 0;
			suite += payload[ctr++] << 8;
			suite += payload[ctr++];

			cipherSuites.push_back(suite);
		}

		compressionMethodLength = payload[ctr++];
		compressionMethods.reserve(compressionMethodLength);

		for (int i = 0; i < compressionMethodLength; i++) {
			compressionMethods.push_back(payload[ctr++]);
		}

		extensionsLength = payload[ctr++] << 8;
		extensionsLength += payload[ctr++];

		unsigned short localExtLen = extensionsLength;


		while (localExtLen > 0) {
			unsigned short type = (payload[ctr++] << 8);
			type += payload[ctr++];
			unsigned short length = (payload[ctr++] << 8);
			length += payload[ctr++];

			//unsigned char* payload = (unsigned char*)malloc(length);
			unsigned char* data = payload + ctr;

			extensions.emplace_back(type, length, data);

			ctr += length;

			localExtLen -= (4 + length);


		}


		return ctr;
	}

	unsigned long parseServerHello(unsigned char payload[], unsigned long counter) {
		unsigned long ctr = counter;

		version = (payload[4] << 8) + payload[5];
		memcpy(random, payload + 6, 32);

		sessionIdLength = payload[ctr++];
		memcpy(sessionId, payload + ctr, sessionIdLength);
		ctr += sessionIdLength;

		unsigned short cipherSuite = (payload[ctr] << 8) + payload[ctr + 1]; ctr += 2;

		cipherSuites.push_back(cipherSuite);
		compressionMethods.push_back(payload[ctr++]);

		if (ctr >= length) return 0;

		extensionsLength = (payload[ctr] << 8) + payload[ctr + 1]; ctr += 2;
		unsigned short localExtLen = extensionsLength;

		while (localExtLen > 0) {
			unsigned short type = (payload[ctr] << 8) + payload[ctr + 1]; ctr += 2;
			unsigned short length = (payload[ctr] << 8) + payload[ctr + 1]; ctr += 2;
			unsigned char* data = payload + ctr;

			extensions.emplace_back(type, length, data);

			ctr += length;

			localExtLen -= (4 + length);
		}

		return 0;
	}

	unsigned long toBytesClientKeyExchange(unsigned char payload[]) {
		memcpy(payload + 4, this->payload, payloadLength);
		return 4 + payloadLength;
	}

	unsigned long toBytesClientFinished(unsigned char payload[]) {
		return toBytesClientKeyExchange(payload); //It behaves literally the same
	}

	unsigned long toBytesClientHello(unsigned char payload[]) {
		unsigned int ctr = 38;

		payload[4] = (version >> 8) & 0xff;
		payload[5] = version & 0xff;
		memcpy(payload + 6, random, 32);

		payload[ctr++] = sessionIdLength;
		memcpy(payload + ctr, sessionId, sessionIdLength);
		ctr += sessionIdLength;

		payload[ctr++] = (cipherSuitesLength >> 8) & 0xff;
		payload[ctr++] = cipherSuitesLength & 0xff;

		for (int i = 0; i < cipherSuitesLength / 2; i++) {
			payload[ctr++] = (cipherSuites[i] >> 8) & 0xff;
			payload[ctr++] = cipherSuites[i] & 0xff;
		}

		payload[ctr++] = compressionMethodLength;

		for (int i = 0; i < compressionMethodLength; i++) {
			payload[ctr++] = compressionMethods[i];
		}

		payload[ctr++] = (extensionsLength >> 8) & 0xff;
		payload[ctr++] = extensionsLength & 0xff;

		for (int i = 0; i < extensions.size(); i++) {
			unsigned short type = extensions[i].getType();
			payload[ctr++] = (type >> 8) & 0xff;
			payload[ctr++] = type & 0xff;

			unsigned short extLength = extensions[i].getLength();
			payload[ctr++] = (extLength >> 8) & 0xff;
			payload[ctr++] = extLength & 0xff;

			memcpy(payload + ctr, extensions[i].getPayload(), extLength);
			ctr += extLength;
		}

		return ctr;

	}

public:
	TLSHandshake() {
		type = 0;
		length = 0;
		version = 0;
		memset(random, 0, 32);
		random[0] = 0xab;
		random[31] = 0xcd;
		memset(random + 2, rand(), 1);
		sessionIdLength = 0;
		memset(sessionId, 0, 32);
		cipherSuitesLength = 0;
		compressionMethodLength = 0;
		extensionsLength = 0;
		payloadLength = 0;
		payload = nullptr;
	}

	TLSHandshake(unsigned char type, unsigned short version) {
		this->type = type;
		length = type == 0x1 || type == 0x2 ? 40 : 0;
		this->version = version;
		memset(random, 0, 32);
		random[0] = 0xab;
		random[31] = 0xcd;
		sessionIdLength = 0;
		memset(sessionId, 0, 32);
		cipherSuitesLength = 0;
		compressionMethodLength = 0;
		extensionsLength = 0;
		payloadLength = 0;
		payload = nullptr;
	}

	~TLSHandshake() {
		if (this->payload != nullptr) {
			free(this->payload);
		}
	}

	unsigned long tobytes(unsigned char payload[]) {

		payload[0] = type;
		payload[1] = (this->length >> 16) & 0xff;
		payload[2] = (this->length >> 8) & 0xff;
		payload[3] = this->length & 0xff;

		switch (type) {
		case 0x1:
			return toBytesClientHello(payload);
			break;
		case 0x2:
			return -1;
			break;
		case 0x10:
			return toBytesClientKeyExchange(payload);
			break;
		case 0x14:
			return toBytesClientFinished(payload);
			break;
		}
	}

	void addCipherSuite(unsigned short suite) {
		cipherSuitesLength += 2;
		length += 2;
		cipherSuites.push_back(suite);
	}

	void addExtension(TLSExtension ext) {
		extensionsLength += 4 + ext.getLength();
		length += 4 + ext.getLength();
		extensions.push_back(ext);
	}

	void addCompressionMethod(unsigned char method) {
		compressionMethods.push_back(method);
		compressionMethodLength++;
		length += 1;
	}

	unsigned long parseBytes(unsigned char payload[]) {
		unsigned int ctr = 38;

		type = payload[0];
		length = (payload[1] << 16) + (payload[2] << 8) + payload[3];

		

		switch (type) {
		case 0x1:
			return parseClientHello(payload, ctr);
			break;
		case 0x2:
			return parseServerHello(payload, ctr);
			break;
		case 0x10:

			return parseClientKeyExchange(payload);
			break;
		}
	}

	unsigned char* getRandom() {
		return random;
	}

	void toString(char buffer[], size_t size) {
		sprintf_s(buffer, size, "Handhsake type: %d, Len: %d, protocol: %d, first random: %x, last random: %x, session id len: %d, suites: %d, first suite: %d, compression method: %d, extensions: %d", type, length, version, random[0], random[31], sessionIdLength, cipherSuitesLength, cipherSuites.front(), compressionMethodLength, extensionsLength);
	}

	unsigned long getLength() {
		return length;
	}

	void setPayload(unsigned char payload[], unsigned long length) {
		if (this->payload == nullptr) {
			this->payload = (unsigned char*)malloc(length);
		}
		else {
			this->payload = (unsigned char*)realloc(this->payload, length);
		}

		memcpy(this->payload, payload, length);
		this->length -= payloadLength;
		payloadLength = length;
		this->length += payloadLength;
	}

	unsigned char * getPayload() {
		return payload;
	}

	void setSessionId(unsigned char* data, unsigned char len) {
		sessionIdLength = len;
		memcpy(sessionId, data, len);
		length += len;
	}

	unsigned char getSessionId(unsigned char* data) {
		memcpy(data, sessionId, sessionIdLength);
		return sessionIdLength;
	}

	std::vector<unsigned short> getCipherSuites() {
		return cipherSuites;
	}

	std::vector<TLSExtension> getExtensions() {
		return extensions;
	}
};

