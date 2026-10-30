// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "cdll.h"
#include "TLSHandshake.h"
#include "crypto.h"

#include <string>
#include <string.h>
#include <stdint.h>

void testing(char buffer[], unsigned long length) {
    strcpy_s(buffer, length, "Hello world");
}

unsigned long parseAndPrint(unsigned char payload[], char printBuffer[], unsigned long size) {
    TLSHandshake shake;
    unsigned long parsed = shake.parseBytes(payload);
    shake.toString(printBuffer, size);
    //sprintf_s(printBuffer, 128, "AHOJ SVETE!");
    //int i;
    return parsed;
}

unsigned long appPut(char buffer[]) {
    return 4;
}

unsigned long parse(unsigned char payload[]) {
    TLSHandshake shake;
    return shake.parseBytes(payload);
}

unsigned long createEmptyHandshake(unsigned long type, unsigned long version, unsigned char out[]) {
    TLSHandshake shake(type, version);
    return shake.tobytes(out);
}

unsigned long createRecord_replace(unsigned long type, unsigned long version, unsigned long payloadLength, unsigned char payload[]) {
    TLSRecord record(type, version, payloadLength, payload);
    //return record.getLength();
    return record.toBytes(payload);
}

unsigned long createRecord(unsigned char type, unsigned short version, unsigned long payloadLength, unsigned char payload[], unsigned char out[]) {
    TLSRecord record(type, version, payloadLength, payload);
    return record.toBytes(out);
}

unsigned long addCompressionMethod(unsigned long method, unsigned char payload[]) {
    TLSHandshake shake;
    shake.parseBytes(payload);
    shake.addCompressionMethod(method);
    return shake.tobytes(payload);
}

unsigned long addCipherSuite(unsigned long suite, unsigned char payload[]) {
    TLSHandshake shake;
    shake.parseBytes(payload);
    shake.addCipherSuite(suite);
    return shake.tobytes(payload);
}

unsigned long addExtension(unsigned long type, unsigned long length, unsigned char extensionData[], unsigned char payload[]) {
    TLSHandshake shake;
    TLSExtension ext(type, length, extensionData);
    shake.parseBytes(payload);
    shake.addExtension(ext);
    return shake.tobytes(payload);
}

void extractRandomFromMessage(unsigned char payload[], unsigned long length, unsigned char random[]) {
    TLSMessage message;
    unsigned long parsed = message.parseBytes(payload, length);

    unsigned char * recordPayload = message.getRecords()[0].getPayload();

    TLSHandshake shake;
    shake.parseBytes(recordPayload);
    memcpy(random, shake.getRandom(), 32);
    
}

unsigned long getRecord(unsigned char payload[], unsigned long length, unsigned long index, unsigned char out[]) {
    
    TLSMessage message;
    message.parseBytes(payload, length);

    TLSRecord rec = message.getRecords()[index];
    return rec.toBytes(out);
}

unsigned long getPayloadFromRecord(unsigned char payload[], unsigned char out[]) {
    TLSRecord record;
    record.parseBytes(payload);
    return record.getPayload(out);
}

unsigned long parseMessage(unsigned char payload[], unsigned long payloadLength) {
    TLSMessage message;
    return message.parseBytes(payload, payloadLength);
}

unsigned long setRecordPayload(unsigned char recordData[], unsigned char payload[], unsigned long length) {
    TLSRecord record;
    record.parseBytes(recordData);
    record.setPayload(payload, length);
    return record.toBytes(recordData);
}

unsigned long replaceRecord(unsigned char payload[], unsigned long length, unsigned long index, unsigned char recordData[]) {
    TLSMessage message;
    message.parseBytes(payload, length);

    TLSRecord record;
    record.parseBytes(recordData);
    message.getRecords()[index] = record;
    //message.getRecords().push_back(record);
    return message.toBytes(payload);
}

unsigned short getCipherSuite(unsigned char payload[], unsigned long len, unsigned long idx) {
    TLSMessage message;
    TLSHandshake handshake;
    message.parseBytes(payload, len);
    handshake.parseBytes(message.getRecords()[0].getPayload());
    return handshake.getCipherSuites()[idx];
}

unsigned long computeKeyBlock(unsigned char handshakeStructData[], unsigned char masterSecret[], unsigned char keyblock[]) {
    unsigned char randoms[64];

    handshakes_t shakes;

    memcpy(&shakes, handshakeStructData, sizeof(handshakes_t));         // Setup the struct

    extractRandomFromMessage(shakes.clientHello, shakes.chLen, randoms + 32);
    extractRandomFromMessage(shakes.serverHello, shakes.shLen, randoms);

    unsigned short cipherSuite = getCipherSuite(shakes.serverHello, shakes.shLen, 0);

    PRF((char*)masterSecret, 48, "key expansion", (char*)randoms, 64, 96, cipherSuite, keyblock);

    return cipherSuite;
}

void computeVerifyData(unsigned char handshakeStructData[], unsigned char masterSecret[], unsigned char verifyData[]) {

    TLSMessage messages[3];
    handshakes_t shakes;
    unsigned char handshakeHash[48];
    unsigned char* allHandshakes;
    int cur = 0;

    memcpy(&shakes, handshakeStructData, sizeof(handshakes_t));         // Setup the struct

    allHandshakes = (unsigned char*)malloc(shakes.chLen + shakes.shLen + shakes.ckeLen);

    messages[0].parseBytes(shakes.clientHello, shakes.chLen);           // Parse all the data
    messages[1].parseBytes(shakes.serverHello, shakes.shLen);
    messages[2].parseBytes(shakes.clientKeyExchange, shakes.ckeLen);


    for (int i = 0; i < 3; i++) {                                       // Construct input for the hash
        for (TLSRecord record : messages[i].getRecords()) {
            record.getPayload(allHandshakes + cur);
            cur += record.getPayloadLength();
            if (i == 2) break;
        }
    }

    unsigned short cipherSuite = getCipherSuite(shakes.serverHello, shakes.shLen, 0);
    unsigned char hashLen = hash(allHandshakes, cur, cipherSuite, handshakeHash);
    
    unhexlify("1400000C", 4, verifyData);                               // Append the handshake header

    PRF((char*)masterSecret, 48, "client finished", (char*)handshakeHash, hashLen, 12, cipherSuite, verifyData);

    free(allHandshakes);
}

/* DEPRECATED
void computeVerifyData(unsigned char clientHello[], unsigned long clientHelloLen, unsigned char serverHello[], unsigned long serverHelloLen, unsigned char clientKeyExchange[], unsigned long clientKeyExhangeLen, unsigned char masterSecret[]) {
    TLSMessage messages[3];

    messages[0].parseBytes(clientHello, clientHelloLen);
    messages[1].parseBytes(serverHello, serverHelloLen);
    messages[2].parseBytes(clientKeyExchange, clientKeyExhangeLen);

    unsigned char* allHandshakes = (unsigned char*)malloc(clientHelloLen + serverHelloLen + clientKeyExhangeLen);

    int cur = 0;

    for (int i = 0; i < 3; i++) {
        for (TLSRecord record : messages[i].getRecords()) {
            record.getPayload(allHandshakes + cur);
            cur += record.getPayloadLength();
            if (i == 2) break;
        }
    }

    unsigned char handshakeHash[32];

    hash(allHandshakes, cur, handshakeHash);

    unsigned char verifyData[16];
    unhexlify("1400000C", 4, verifyData);

    PRF((char*)masterSecret, 48, "client finished", (char*)handshakeHash, 32, 12, verifyData + 4);


    memcpy(clientKeyExchange + clientKeyExhangeLen - 40, verifyData, 16);
}*/


unsigned long encryptData(unsigned char data[], unsigned long dataLen, unsigned long cipherSuite, unsigned char keyblock[], unsigned long long seq, unsigned char out[], unsigned long encryptThenMac) {
    unsigned char key[16];
    unsigned char iv[4];

    memcpy(key, keyblock, 16);
    memcpy(iv, keyblock + 32, 4); 

    //aes128gcm_encrypt(data, dataLen, key, "12345678", iv, out, seq);

    keyblock_t kb;
    memcpy(&kb, keyblock, sizeof(keyblock_t));

    unsigned char test[50] = {0};

    return tls_encrypt(cipherSuite, data, dataLen, "12345678", kb, out, seq, encryptThenMac);
}



unsigned long encryptDataMacThenEncrypt(unsigned char data[], unsigned long dataLen, unsigned long cipherSuite, unsigned char keyblock[], unsigned long long seq, unsigned char out[]) {
    return encryptData(data, dataLen, cipherSuite, keyblock, seq, out, 0);
}

unsigned long encryptDataEncryptThenMac(unsigned char data[], unsigned long dataLen, unsigned long cipherSuite, unsigned char keyblock[], unsigned long long seq, unsigned char out[]) {
    return encryptData(data, dataLen, cipherSuite, keyblock, seq, out, 1);
}

// NOT IMPLEMENTED PROPERLY
void decryptVerifyData(unsigned char clientHello[], unsigned long clientHelloLen, unsigned char serverHello[], unsigned long serverHelloLen, unsigned char serverFinished[], unsigned long serverFinishedLen, unsigned char masterSecret[]) {
    unsigned char clientRandom[32];
    unsigned char serverRadnom[32];

    extractRandomFromMessage(clientHello, clientHelloLen, clientRandom);
    extractRandomFromMessage(serverHello, serverHelloLen, serverRadnom);


    unsigned char keyblock[40];
    unsigned char serverClientRandom[64];

    memcpy(serverClientRandom, serverRadnom, 32);
    memcpy(serverClientRandom + 32, clientRandom, 32);

    PRF((char*)masterSecret, 48, "key expansion", (char*)serverClientRandom, 64, 40, 256, keyblock);

    unsigned char serverWrite[16];
    unsigned char serverIv[4];

    memcpy(serverWrite, keyblock + 16, 16);
    memcpy(serverIv, keyblock + 36, 4);

    //aes128gcm_decrypt(serverFinished + serverFinishedLen - 40 + 8, serverWrite, (char*)(serverFinished + serverFinishedLen - 40), serverIv, serverFinished);
  
}

int findEMS(unsigned char payload[], unsigned long len) {

    TLSMessage hello;
    hello.parseBytes(payload, len);

    TLSHandshake shake;
    shake.parseBytes(hello.getRecords()[0].getPayload());
    
    for (TLSExtension ext : shake.getExtensions()) {
        if (ext.getType() == 0x0017) return 1;
    }

    return 0;
}

void computeMasterSecret(unsigned char PSK[], unsigned long PSKLen, unsigned char handshakeStructData[], unsigned char masterSecret[]) {
    TLSMessage messages[3];
    handshakes_t shakes;
    uint16_t len = swapEndianShort(PSKLen);
    unsigned char* premaster = (unsigned char*)calloc(2 * PSKLen + 4, 1);
    unsigned char handshakeHash[48];
    unsigned short cipherSuite;
    int cur = 0;


    memcpy(&shakes, handshakeStructData, sizeof(handshakes_t));         // Setup the struct

    memcpy(premaster, &len, 2);                                         // Setup premaster
    memcpy(premaster + PSKLen + 2, &len, 2);
    memcpy(premaster + PSKLen + 4, PSK, PSKLen);


    messages[0].parseBytes(shakes.clientHello, shakes.chLen);           // Parse messages
    messages[1].parseBytes(shakes.serverHello, shakes.shLen);
    messages[2].parseBytes(shakes.clientKeyExchange, shakes.ckeLen);

    cipherSuite = getCipherSuite(shakes.serverHello, shakes.shLen, 0);
   

    if (findEMS(shakes.clientHello, shakes.chLen)) {

        unsigned char * allHandshakes = (unsigned char*)malloc(shakes.chLen + shakes.shLen + shakes.ckeLen);

        for (int i = 0; i < 3; i++) {
            for (TLSRecord record : messages[i].getRecords()) {

                record.getPayload(allHandshakes + cur);
                cur += record.getPayloadLength();
                if (i == 2) break;
            }
        }

        unsigned char hashLen = hash(allHandshakes, cur, cipherSuite, handshakeHash);

        PRF((char*)premaster, 2 * PSKLen + 4, "extended master secret", (char*)handshakeHash, hashLen, 48, cipherSuite, masterSecret);
        free(allHandshakes);

    } else {

        unsigned char bothSecrets[64];

        extractRandomFromMessage(shakes.clientHello, shakes.chLen, bothSecrets);
        extractRandomFromMessage(shakes.serverHello, shakes.shLen, bothSecrets + 32);

        PRF((char*)premaster, 2 * PSKLen + 4, "master secret", (char*)bothSecrets, 64, 48, cipherSuite, masterSecret);
    }

    free(premaster);
}

unsigned long handshakeSetPayload(unsigned char handshake[], unsigned char payload[], unsigned long payloadLength) { 
    TLSHandshake shake;
    shake.parseBytes(handshake);
    shake.setPayload(payload, payloadLength);
    return shake.tobytes(handshake);
}

unsigned long setHandshakeSessionId(unsigned char payload[], unsigned char sessionId[], unsigned long len) {
    TLSHandshake shake;
    shake.parseBytes(payload);
    shake.setSessionId(sessionId, len);
    return shake.tobytes(payload);
}

unsigned long getHandshakeSessionId(unsigned char payload[], unsigned char sessionId[]) {
    TLSHandshake shake;
    shake.parseBytes(payload);
    return shake.getSessionId(sessionId);

}

void injectFaultTag(unsigned char payload[], unsigned long len, unsigned long cipherSuite) {
    
    switch (cipherSuite) {
    case TLS_PSK_WITH_AES_128_GCM_SHA256:
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
    case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_PSK_WITH_AES_128_CBC_SHA256:
        payload[len - 1] ^= 0xff;
    }
    // TODO rest of ciphers
}

void injectFaultInitVector(unsigned char keyblock[], unsigned long cipherSuite) {
    switch (cipherSuite) {
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
        keyblock[64] ^= 0xff;
        break;
    case TLS_PSK_WITH_AES_128_GCM_SHA256:
    case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
        keyblock[32] ^= 0xff;
        break;
    case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        keyblock[64] ^= 0xff;
    default:
        break;
    }

}

__declspec(dllexport)
void injectFaultData(unsigned char payload[], unsigned long cipherSuite) {
    
    switch (cipherSuite)
    {
    case TLS_PSK_WITH_AES_128_GCM_SHA256:
    case TLS_PSK_WITH_AES_256_GCM_SHA384:
        payload[8] ^= 0xff;
    case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
    case TLS_PSK_WITH_AES_128_CBC_SHA256:
        payload[0] ^= 0xff;
    default:
        break;
    }
}

unsigned long findExtensionInRecord(unsigned char payload[], unsigned long extensionNumber) {
    TLSRecord record;
    record.parseBytes(payload);

    TLSHandshake shake;
    shake.parseBytes(record.getPayload());

    if (shake.getExtensions().size() == 0) return 0;

    for (TLSExtension ext : shake.getExtensions()) {

        if (ext.getType() == extensionNumber) {
            
            return 1;
        }
    }

    return 0;
}

CAPL_DLL_INFO4 info_table[] =
{
{CDLL_VERSION_NAME, (CAPL_FARCALL)CDLL_VERSION, "", "", CAPL_DLL_CDECL, 0xabcd, CDLL_EXPORT },
//    {"dllTest",                 (CAPL_FARCALL)testing,                  "CAPL_DLL", "Only test", 'V', 2, "CD", "\001\000", {"buffer", "length"}},
//    {"dllPut",                  (CAPL_FARCALL)appPut,                   "CAPL_DLL", "This function will save data from CAPL to DLL memory",'D', 1, "C", "\001", {"buffer"}},
//   {"parsePrint",              (CAPL_FARCALL)parseAndPrint,            "CAPL_DLL", "Parses and prints", 'D', 3, "BCD", "\001\001\000", {"payload", "printBuffer", "size"}},
    
    // Message
    {"TLS_message_parse",        (CAPL_FARCALL)parseMessage,             "CAPL_DLL", "Parses a TLS Message, return number of records", 'L', 2, "BD", "\001\000", {"payload", "payloadLength"}},
    {"TLS_message_getServerRandom", (CAPL_FARCALL)extractRandomFromMessage,"CAPL_DLL", "Extracts the server random bytes from a whole packet", 'V', 3, "BDB", "\001\000\001", {"payload", "length", "random"}},
    {"TLS_message_getRecord", (CAPL_FARCALL)getRecord,               "CAPL_DLL", "Gets the n-th record from TLS Message, returns the length of the record", 'L', 4, "BDDB", "\001\000\000\001", {"payload", "length", "index", "out"}},
    {"TLS_message_replaceRecord", (CAPL_FARCALL)replaceRecord,          "CAPL_DLL", "Replaces a record in a TLS message, returns the new length of the whole message", 'L', 4, "BDDB", "\001\000\000\001", {"payload", "length", "index", "recordData"}},
    
    // Record
    {"TLS_record_findExtension", (CAPL_FARCALL)findExtensionInRecord, "CAPL_DLL", "Find an extension by number", 'D', 2, "BD", "\001\000", {"payload", "extensionNumber"}},
    {"TLS_record_getPayload", (CAPL_FARCALL)getPayloadFromRecord,    "CAPL_DLL", "Gets the payload from TLSRecord, return the length of the payload", 'L', 2, "BB", "\001\001", {"payload", "out"}},
    {"TLS_record_setPayload", (CAPL_FARCALL)setRecordPayload,            "CAPL_DLL", "Sets the payload for a TLSRecord, returns the new length of the record", 'L', 3, "BBD", "\001\001\000", {"recordData", "payload", "length"}},
    //{"TLS_createRecord_repl",   (CAPL_FARCALL)createRecord_replace,     "CAPL_DLL", "Creates a TLS Record and sets its data (replaces the input data), returns the length of the record", 'L', 4, "DDDB", "\000\000\000\001", {"type", "version", "payloadLength", "payload"}},
    {"TLS_record_create",        (CAPL_FARCALL)createRecord,              "CAPL_DLL", "Creates a TLS Record and sets its data, returns the length of the record", 'L', 5, "DDDBB", "\000\000\000\001\001", {"type", "version", "payloadLength", "payload", "out"}},

    // Handshake
    {"TLS_handshake_parse",        (CAPL_FARCALL)parse,                  "CAPL_DLL", "Testing toBytes", 'D', 1, "B", "\001", {"payload"}},
    {"TLS_handshake_setSessionId", (CAPL_FARCALL)setHandshakeSessionId, "CAPL_DLL", "Add handshake", 'D', 3, "BBD", "\001\001\000", {"payload", "sessionId", "sessionIdLen"}},
    {"TLS_handshake_getSessionId", (CAPL_FARCALL)getHandshakeSessionId, "CAPL_DLL", "Get handhsake sessionId", 'D', 1, "B", "\001", {"pyload"}},
    {"TLS_handshake_createEmpty",      (CAPL_FARCALL)createEmptyHandshake,     "CAPL_DLL", "Creates an empty TLS handshake, returns the length of the handshake", 'L', 3, "DDB", "\000\000\001", {"type", "version", "out"}},
    {"TLS_handshake_addCompressionMethod", (CAPL_FARCALL)addCompressionMethod, "CAPL_DLL", "Adds a compression method to a TLS Handshake message, returns the total length of the handshake", 'L', 2, "DB", "\000\001", {"method", "payload"}},
    {"TLS_handshake_addCipherSuite", (CAPL_FARCALL)addCipherSuite,       "CAPL_DLL", "Add a cipher suite to a TLS Handshake message, returns the total length of the handshake", 'L', 2, "DB", "\000\001", {"suite", "payload"}},
    {"TLS_handshake_addExtension", (CAPL_FARCALL)addExtension,           "CAPL_DLL", "Add an extension to a TlS Handshake message, returns the total length of the handshake", 'L', 4, "DDBB", "\000\000\001\001", {"type", "length", "extensionData", "payload"}},
    {"TLS_handshake_setPayload", (CAPL_FARCALL)handshakeSetPayload, "CAPL_DLL", "Set handshake payload", 'D', 3, "BBD", "\001\001\000", {"handshake", "payload", "payLoadLength"}},

    // Crypto
    
    {"TLS_crypto_computeVerifyData", (CAPL_FARCALL)computeVerifyData, "CAPL_DLL", "", 'V', 3, "BBB", "\001\001\001", {"handshakesStructData", "masterSecret", "verifyDataOut"}},
    {"TLS_crypto_computeMasterSecret", (CAPL_FARCALL)computeMasterSecret, "CAPL_DLL", "", 'V', 4, "BDBB", "\001\000\001\001", {"PSK", "PSKLen", "handshakesStructData", "masterSecretOut"}},
    {"TLS_crypto_computeKeyblock", (CAPL_FARCALL)computeKeyBlock, "CAPL_DLL", "Compute keyblock for crypto, returns the cipher suite", 'D', 3, "BBB", "\001\001\001", {"handshakesStructData", "masterSecret", "keyblockOut"}},
    {"TLS_crypto_encryptDataEncryptThenMac", (CAPL_FARCALL)encryptDataEncryptThenMac, "CAPL_DLL", "Encrypt data", 'D', 6, "BDDBUB", "\001\000\000\001\000\001", {"data", "dataLen", "cipherSuite", "keyblock", "sequenceNumber", "out"}},
    {"TLS_crypto_encryptData", (CAPL_FARCALL)encryptDataMacThenEncrypt, "CAPL_DLL", "Encrypt data", 'D', 6, "BDDBUB", "\001\000\000\001\000\001", {"data", "dataLen", "cipherSuite", "keyblock", "sequenceNumber", "out"}},
    
    // Disabled for now
    //{"TLS_crypto_decryptVerifyData", (CAPL_FARCALL)decryptVerifyData, "CAPL_DLL", "Decrypt server verify data", 'V', 7, "BDBDBDB", "\001\000\001\000\001\000\001", {"clientHello", "CHLen", "serverHello", "SHLen", "serverFinished", "SFLen", "master secret"}},
    
    // Fault inject
    {"TLS_faultInject_initVector", (CAPL_FARCALL)injectFaultInitVector, "CAPL_DLL", "Invalidate the init vector for ecnryption", 'V', 2, "BD", "\001\000", {"keylbock", "cipherSuite"}},
    {"TLS_faultInject_authenticationTag", (CAPL_FARCALL)injectFaultTag, "CAPL_DLL", "Invalidate the authentication tag or HMAC", 'V', 3, "BDD", "\001\000\000", {"payload", "payloadLen", "cipherSuite"}},
    {"TLS_faultInject_data", (CAPL_FARCALL)injectFaultData, "CAPL_DLL", "Invalidate encrypted data", 'V', 2, "BD", "\001\000", {"payload", "cipherSuite"}},
{0, 0}
};

CAPLEXPORT CAPL_DLL_INFO4* caplDllTable4 = info_table;