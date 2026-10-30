#pragma once
#include "utils.h"

extern int destructorCalls = 0;
extern int bilance = 0;

class TLSExtension {
private:
	unsigned short type;
	unsigned short length;
	unsigned char* payload;

public:
	TLSExtension(unsigned short type, unsigned short length, unsigned char* payload) {
		this->type = type;
		this->length = length;
		//this->payload = nullptr;
		this->payload = (unsigned char*)malloc(length);
		memcpy(this->payload, payload, length);
		bilance++;
	}

	TLSExtension(const TLSExtension& other): type(other.type), length(other.length) {
		if (other.payload != nullptr) {
			payload = (unsigned char*)malloc(length);
			bilance++;
			memcpy(payload, other.payload, length);
		} else {
			payload = nullptr;
		}
	}

	TLSExtension& operator=(const TLSExtension& other) {
		if (this == &other) return *this;

		type = other.type;
		length = other.length;

		free(payload);
		bilance--;
		if (other.payload != nullptr) {
			payload = (unsigned char*)malloc(length);
			bilance++;
			memcpy(payload, other.payload, length);
		} else {
			payload = nullptr;
		}

		return *this;
	}

	TLSExtension(TLSExtension&& other) noexcept : type(other.type), length(other.length), payload(other.payload) {
		other.payload = nullptr;
	}

	TLSExtension& operator=(TLSExtension&& other) noexcept {
		if (this == &other) return *this;

		free(payload);
		bilance--;

		type = other.type;
		length = other.length;
		payload = other.payload;

		other.payload = nullptr;

		return *this;
	}

	~TLSExtension() {
		destructorCalls += 1;
		if (payload != nullptr) bilance--;
		free(payload);
	}

	unsigned short getLength() {
		return length;
	}

	unsigned short getType() {
		return type;
	}

	unsigned char* getPayload() {
		return payload;
	}

	void setLength(unsigned short length) {
		this->length = length;
		if (payload == nullptr) {
			payload = (unsigned char*)malloc(length);
		} else {
			payload = (unsigned char*)realloc(payload, length);
		}

	}

	void setType(unsigned short type) {
		this->type = type;
	}

	void setPayload(unsigned char* payload) {
		memcpy(this->payload, payload, length);
	}
};

class TLSRecord {

private:
	unsigned char contentType;
	unsigned short protocolVersion;
	unsigned short payloadLength;
	unsigned char* payload;
	unsigned long totalLength;

public:
	TLSRecord() {
	
	}

	TLSRecord(unsigned char contentType, unsigned short protocolVersion, unsigned long payloadLength, unsigned char* payload) : contentType(contentType), protocolVersion(protocolVersion), payloadLength(payloadLength) {
		
		//memcpy(&payloadLength, payload, 4);
		//payloadLength = (swapEndianLong(payloadLength) & 0xffffff) + 4;
		//payloadLength += 4;

		this->payload = (unsigned char*)malloc(payloadLength);
		memcpy(this->payload, payload, payloadLength);
		
		totalLength = payloadLength + 5;
	}

	// Copy Constructor
	TLSRecord(const TLSRecord& other) : contentType(other.contentType), protocolVersion(other.protocolVersion), payloadLength(other.payloadLength) {
		payload = (unsigned char*)malloc(payloadLength);
		memcpy(payload, other.payload, payloadLength);
		totalLength = payloadLength + 5;
	}

	// Copy Assignment
	TLSRecord& operator=(const TLSRecord& other) {
		if (this != &other) {
			// Free old payload
			free(payload);

			contentType = other.contentType;
			protocolVersion = other.protocolVersion;
			payloadLength = other.payloadLength;

			payload = (unsigned char*)malloc(payloadLength);
			if (!payload) throw std::bad_alloc();

			memcpy(payload, other.payload, payloadLength);
			totalLength = payloadLength + 5;
		}
		return *this;
	}

	// Move Constructor
	TLSRecord(TLSRecord&& other) noexcept : contentType(other.contentType), protocolVersion(other.protocolVersion), payloadLength(other.payloadLength), payload(other.payload) {
		other.payload = nullptr;
		other.payloadLength = 0;
	}

	// Move Assignment Operator
	TLSRecord& operator=(TLSRecord&& other) noexcept {

		if (this == &other) return *this;
		free(payload);

		contentType = other.contentType;
		protocolVersion = other.protocolVersion;
		payloadLength = other.payloadLength;
		payload = other.payload;

		other.payload = nullptr;
		other.payloadLength = 0;
	}

	unsigned long parseBytes(unsigned char payload[]) {
		unsigned long ctr = 0;
		contentType = payload[ctr++];
		protocolVersion = payload[ctr++] << 8;
		protocolVersion += payload[ctr++];
		payloadLength = payload[ctr++] << 8;
		payloadLength += payload[ctr++];

		this->payload = (unsigned char*)malloc(payloadLength);
		memcpy(this->payload, payload + ctr, payloadLength);

		totalLength = payloadLength + 5;
		return totalLength;
	}

	unsigned long getPayloadLength() {
		return payloadLength;
	}

	unsigned long getTotalLength() {
		return totalLength;
	}

	unsigned char getType() {
		return contentType;
	}

	unsigned long getPayload(unsigned char out[]) {
		if (payload == nullptr) {
			return 99;
		}
		memcpy(out, payload, payloadLength);
		return payloadLength;
	}

	unsigned char* getPayload() {
		return payload;
	}

	unsigned long setPayload(unsigned char payload[], unsigned long length) {
		this->payload = (unsigned char*)realloc(this->payload, length);
		memcpy(this->payload, payload, length);
		payloadLength = length;
		totalLength = length + 5;

		return totalLength;
	}

	~TLSRecord() {
		if (payload != nullptr) {
			free(payload);
		}
	}

	unsigned long toBytes(unsigned char* payload) {
		payload[0] = contentType;
		payload[1] = (protocolVersion >> 8) & 0xff;
		payload[2] = protocolVersion & 0xff;
		payload[3] = (payloadLength >> 8) & 0xff;
		payload[4] = payloadLength & 0xff;
		memcpy(payload + 5, this->payload, payloadLength);
		return totalLength;
	}
};

class TLSMessage {

private:
	std::vector<TLSRecord> records;

public:	

	void emplaceRecord(unsigned char type, unsigned short version, unsigned long pyloadLength, unsigned char payload[]) {
		records.emplace_back(type, version, pyloadLength, payload);
	}

	unsigned long parseBytes(unsigned char payload[], unsigned long length) {	

		

		unsigned long records = 0;
		unsigned long len = length;
		unsigned long ctr = 0;

		while (len > 0) {
			
			unsigned char type = payload[ctr++];

			if (type == 0) {
				break;
			}

			unsigned short version = payload[ctr++] << 8;
			version += payload[ctr++];
			unsigned short pyloadLength = payload[ctr++] << 8;
			pyloadLength += payload[ctr++];

			emplaceRecord(type, version, pyloadLength, payload + ctr);
			ctr += pyloadLength;
			len -= (pyloadLength + 5);

			records++;
			
				
		}

		return records;
	}

	unsigned long toBytes(unsigned char payload[]) {
		unsigned long ctr = 0;

		for (auto rec : records) {
			ctr += rec.toBytes(payload + ctr);
		}

		return ctr;
	}

	std::vector<TLSRecord>& getRecords() {
		return records;
	}
};
