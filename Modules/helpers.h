#ifndef MODULES_HELPERS_H_
#define MODULES_HELPERS_H_

#include <omnetpp.h>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <queue>
using namespace omnetpp;
using namespace std;

/*
Hybrid TCP-UDP Secure Transmission Protocol
Message kinds:
  // TCP Protocol Messages
  30 = TCP_SYN          // TCP connection initiation
  31 = TCP_SYN_ACK      // TCP connection acknowledgment
  32 = TCP_ACK          // TCP acknowledgment
  33 = TCP_DATA         // TCP reliable data transfer
  34 = TCP_FIN          // TCP connection termination
  
  // UDP Protocol Messages
  40 = UDP_DATA         // UDP low-latency data transfer
  
  // Security Messages
  50 = KEY_EXCHANGE     // ECDH key exchange
  51 = ENCRYPTED_DATA   // AES encrypted data
  
  // DNS Messages (Enhanced)
  10 = DNS_QUERY
  11 = DNS_RESPONSE
  
  // HTTP Messages (Enhanced)
  20 = HTTP_GET
  21 = HTTP_RESPONSE
  
  // Routing Protocol Messages
  60 = OSPF_HELLO       // OSPF neighbor discovery
  61 = OSPF_LSA         // OSPF Link State Advertisement
  62 = OSPF_TE_UPDATE   // OSPF Traffic Engineering update
  63 = RIP_UPDATE       // RIP distance vector update
  64 = RIP_REQUEST      // RIP route request

For all messages we set:
  par("src") : long  logical sender address
  par("dst") : long  logical destination address
  par("seq") : long  sequence number (for TCP)
  par("ack") : long  acknowledgment number (for TCP)
  par("priority") : int (0=low, 1=normal, 2=high, 3=critical)
  par("protocol") : string ("TCP" or "UDP")
  
Security parameters:
  par("publicKey") : string  ECDH public key (hex string)
  par("encData") : string    AES encrypted payload (hex string)
  par("iv") : string         AES initialization vector
  
Routing parameters:
  par("metric") : double     Route metric/cost
  par("bandwidth") : double  Available bandwidth (Mbps)
  par("delay") : double      Link delay (ms)
  par("hopCount") : int      Number of hops
*/

enum {
    // DNS
    DNS_QUERY=10, DNS_RESPONSE=11,
    // HTTP
    HTTP_GET=20, HTTP_RESPONSE=21,
    // TCP
    TCP_SYN=30, TCP_SYN_ACK=31, TCP_ACK=32, TCP_DATA=33, TCP_FIN=34,
    // UDP
    UDP_DATA=40,
    // Security
    KEY_EXCHANGE=50, ENCRYPTED_DATA=51,
    // Routing
    OSPF_HELLO=60, OSPF_LSA=61, OSPF_TE_UPDATE=62,
    RIP_UPDATE=63, RIP_REQUEST=64,
    // BGP
    BGP_UPDATE=70, BGP_KEEPALIVE=71,
    // Application layer
    MAIL_REQUEST=80, MAIL_RESPONSE=81,
    VIDEO_REQUEST=82, VIDEO_CHUNK=83,
    DB_QUERY=84, DB_RESPONSE=85
};

// Priority levels for traffic management
enum Priority {
    PRIORITY_LOW = 0,
    PRIORITY_NORMAL = 1,
    PRIORITY_HIGH = 2,
    PRIORITY_CRITICAL = 3
};

// Connection states for TCP
enum TCPState {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_TIME_WAIT
};

// Routing table entry
struct RouteEntry {
    long destAddr;
    int nextHop;           // gate index
    double metric;
    double bandwidth;      // Available bandwidth in Mbps
    double delay;          // Link delay in ms
    int hopCount;
    simtime_t lastUpdate;
    
    RouteEntry() : destAddr(0), nextHop(-1), metric(INFINITY), 
                   bandwidth(0), delay(0), hopCount(999), lastUpdate(0) {}
};

// Link state for OSPF
struct LinkState {
    long routerId;
    int linkId;
    double cost;
    double bandwidth;
    double delay;
    simtime_t timestamp;
    
    LinkState() : routerId(0), linkId(-1), cost(1.0), 
                  bandwidth(100.0), delay(1.0), timestamp(0) {}
};

// Connection tracking for TCP
struct TCPConnection {
    long remoteAddr;
    TCPState state;
    long sendSeq;
    long recvSeq;
    double cwnd;           // Congestion window
    double ssthresh;       // Slow start threshold
    simtime_t rtt;         // Round trip time
    simtime_t lastSent;
    string sharedKey;      // AES shared key (after ECDH)
    
    TCPConnection() : remoteAddr(0), state(TCP_CLOSED), sendSeq(0), 
                      recvSeq(0), cwnd(1.0), ssthresh(64.0), 
                      rtt(0), lastSent(0), sharedKey("") {}
};

// SYN Cookie generation (simplified)
static long generateSYNCookie(long src, long dst, long seq) {
    // Simplified SYN cookie: hash of src, dst, seq, and secret
    long secret = 0x5EED;  // In production, use time-varying secret
    return ((src ^ dst ^ seq ^ secret) & 0xFFFFFF) | (seq << 24);
}

static bool validateSYNCookie(long cookie, long src, long dst, long seq) {
    long expected = generateSYNCookie(src, dst, seq);
    return (cookie & 0xFFFFFF) == (expected & 0xFFFFFF);
}

// Simple AES simulation (placeholder - in production use real crypto library)
static string simpleEncrypt(const string& data, const string& key) {
    string encrypted;
    for (size_t i = 0; i < data.length(); i++) {
        encrypted += (char)(data[i] ^ key[i % key.length()] ^ 0xAA);
    }
    return encrypted;
}

static string simpleDecrypt(const string& data, const string& key) {
    return simpleEncrypt(data, key); // XOR is symmetric
}

// ECDH key exchange simulation (simplified)
static string generateECDHPublicKey(long address) {
    // Simplified: just generate a pseudo-key based on address
    stringstream ss;
    ss << hex << (address * 0x12345 + 0x6789ABCD);
    return ss.str();
}

static string computeSharedSecret(const string& myPrivate, const string& theirPublic) {
    // Simplified: combine keys
    stringstream ss;
    ss << myPrivate << theirPublic;
    string combined = ss.str();
    string secret;
    for (size_t i = 0; i < 16; i++) { // 128-bit key
        secret += (char)((combined[i % combined.length()] ^ 0x5A) + i);
    }
    return secret;
}

// Helper functions
static cPacket* mk(const char* name, int kind, long src, long dst) {
    auto *m = new cPacket(name, kind);
    m->addPar("src").setLongValue(src);
    m->addPar("dst").setLongValue(dst);
    m->addPar("seq").setLongValue(0);
    m->addPar("ack").setLongValue(0);
    m->addPar("priority").setLongValue(PRIORITY_NORMAL);
    m->setByteLength(1000);  // Default packet size
    return m;
}

static inline long SRC(cMessage* m){ return m->par("src").longValue(); }
static inline long DST(cMessage* m){ return m->par("dst").longValue(); }
static inline long SEQ(cMessage* m){ return m->par("seq").longValue(); }
static inline long ACK(cMessage* m){ return m->par("ack").longValue(); }
static inline int PRIORITY(cMessage* m){ return m->par("priority").longValue(); }

// Priority comparison for queue ordering
struct MessagePriorityCompare {
    bool operator()(cMessage* a, cMessage* b) {
        return PRIORITY(a) < PRIORITY(b); // Higher priority first
    }
};

#endif // MODULES_HELPERS_H_
