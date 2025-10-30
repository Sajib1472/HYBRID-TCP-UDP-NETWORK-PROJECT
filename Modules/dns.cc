
#include <omnetpp.h>
#include "helpers.h"
#include <map>
#include <sstream>
#include <queue>
using namespace omnetpp;
using namespace std;

class DNS : public cSimpleModule {
  private:
    int addr = 0;
    int answer = 3; // HTTP server address
    
    // Security
    map<long, string> sharedKeys;
    string myPublicKey;
    string myPrivateKey;
    
    // SYN flood protection & rate limiting
    map<long, int> requestCounts;
    map<long, simtime_t> lastRequestTime;
    double rateLimit;
    cMessage* rateLimitResetTimer;
    
    // TCP connections
    map<long, TCPConnection> tcpConnections;
    
    // Priority queue for handling requests
    priority_queue<cMessage*, vector<cMessage*>, MessagePriorityCompare> requestQueue;
    
    // Transmission queue management
    cQueue txQueue;
    cMessage* endTxEvent;
    
  protected:
    void initialize() override {
        addr   = par("address");
        answer = par("answerAddr");
        rateLimit = par("rateLimit").doubleValue();
        
        // Initialize security
        myPrivateKey = generateECDHPublicKey(addr);
        myPublicKey = generateECDHPublicKey(addr * 2);
        
        rateLimitResetTimer = new cMessage("rateLimitReset");
        scheduleAt(simTime() + 1.0, rateLimitResetTimer);
        
        // Initialize transmission queue
        txQueue.setName("txQueue");
        endTxEvent = nullptr;
        
        EV_INFO << "DNS server " << addr << " initialized with rate limit " << rateLimit << "\n";
    }

    void handleMessage(cMessage *msg) override {
        if (msg->isSelfMessage()) {
            if (msg == rateLimitResetTimer) {
                requestCounts.clear();
                scheduleAt(simTime() + 1.0, rateLimitResetTimer);
            } else if (msg == endTxEvent) {
                // Transmission finished, send next packet if available
                endTxEvent = nullptr;
                if (!txQueue.isEmpty()) {
                    cMessage* nextMsg = (cMessage*)txQueue.pop();
                    startTransmission(nextMsg);
                }
            }
            return;
        }
        
        int kind = msg->getKind();
        long src = SRC(msg);
        
        // Rate limiting check
        requestCounts[src]++;
        if (requestCounts[src] > rateLimit) {
            EV_WARN << "DNS " << addr << " rate limit exceeded for " << src << ", dropping request\n";
            delete msg;
            return;
        }
        
        switch (kind) {
            case KEY_EXCHANGE:
                handleKeyExchange(msg);
                break;
            case TCP_SYN:
                handleTCPSyn(msg);
                break;
            case TCP_ACK:
                handleTCPAck(msg);
                break;
            case TCP_DATA:
                handleTCPData(msg);
                break;
            case DNS_QUERY:
                handleDNSQuery(msg);
                break;
            default:
                EV_WARN << "DNS unexpected kind=" << kind << "\n";
                delete msg;
        }
    }
    
    // Transmission queue management functions
    void sendPacketOnGate(cMessage* msg) {
        cGate* outGate = gate("ppp$o");
        
        // Check if channel is busy
        simtime_t finishTime = outGate->getTransmissionChannel()->getTransmissionFinishTime();
        if (finishTime > simTime()) {
            // Channel busy, queue the packet
            txQueue.insert(msg);
            EV_INFO << "DNS" << addr << " channel busy, queued packet " << msg->getName() << "\n";
        } else if (endTxEvent != nullptr) {
            // Already transmitting, queue the packet
            txQueue.insert(msg);
            EV_INFO << "DNS" << addr << " transmission in progress, queued packet " << msg->getName() << "\n";
        } else {
            // Channel free, send immediately
            startTransmission(msg);
        }
    }
    
    void startTransmission(cMessage* msg) {
        cGate* outGate = gate("ppp$o");
        send(msg, outGate);
        
        // Schedule end of transmission
        cChannel* channel = outGate->getTransmissionChannel();
        simtime_t finishTime = channel->getTransmissionFinishTime();
        
        if (endTxEvent == nullptr) {
            endTxEvent = new cMessage("endTx");
        } else {
            // Cancel if already scheduled
            if (endTxEvent->isScheduled()) {
                cancelEvent(endTxEvent);
            }
        }
        scheduleAt(finishTime, endTxEvent);
        EV_INFO << "DNS" << addr << " started transmission of " << msg->getName() << ", finish at " << finishTime << "\n";
    }
    
    void handleKeyExchange(cMessage* msg) {
        long peerAddr = SRC(msg);
        string peerPublicKey = msg->par("publicKey").stringValue();
        
        // Compute shared secret
        string sharedSecret = computeSharedSecret(myPrivateKey, peerPublicKey);
        sharedKeys[peerAddr] = sharedSecret;
        
        // If this is a request (no shared key yet), send our public key
        if (sharedKeys.find(peerAddr) == sharedKeys.end() || 
            sharedKeys[peerAddr].empty()) {
            auto* response = mk("KEY_EXCHANGE", KEY_EXCHANGE, addr, peerAddr);
            response->addPar("publicKey").setStringValue(myPublicKey.c_str());
            response->par("priority").setLongValue(PRIORITY_HIGH);
            sendPacketOnGate(response);
        }
        
        sharedKeys[peerAddr] = sharedSecret;
        EV_INFO << "DNS " << addr << " completed key exchange with " << peerAddr << "\n";
        delete msg;
    }
    
    void handleTCPSyn(cMessage* msg) {
        long src = SRC(msg);
        long seq = SEQ(msg);
        long cookie = msg->par("synCookie").longValue();
        
        // Validate SYN cookie (protection against SYN flooding)
        if (!validateSYNCookie(cookie, src, addr, seq)) {
            EV_WARN << "DNS " << addr << " invalid SYN cookie from " << src << "\n";
            delete msg;
            return;
        }
        
        // Send SYN-ACK
        long serverSeq = intuniform(1000, 9999);
        auto* synAck = mk("TCP_SYN_ACK", TCP_SYN_ACK, addr, src);
        synAck->par("seq").setLongValue(serverSeq);
        synAck->par("ack").setLongValue(seq + 1);
        synAck->par("priority").setLongValue(PRIORITY_HIGH);
        synAck->addPar("synCookie").setLongValue(generateSYNCookie(addr, src, serverSeq));
        sendPacketOnGate(synAck);
        
        // Create TCP connection
        TCPConnection conn;
        conn.remoteAddr = src;
        conn.state = TCP_SYN_RECEIVED;
        conn.sendSeq = serverSeq + 1;
        conn.recvSeq = seq + 1;
        tcpConnections[src] = conn;
        
        EV_INFO << "DNS " << addr << " sent SYN-ACK to " << src << "\n";
        delete msg;
    }
    
    void handleTCPAck(cMessage* msg) {
        long src = SRC(msg);
        
        auto it = tcpConnections.find(src);
        if (it != tcpConnections.end() && it->second.state == TCP_SYN_RECEIVED) {
            it->second.state = TCP_ESTABLISHED;
            EV_INFO << "DNS " << addr << " TCP connection established with " << src << "\n";
        }
        delete msg;
    }
    
    void handleTCPData(cMessage* msg) {
        // DNS query received over TCP
        if (msg->hasPar("qname")) {
            handleDNSQuery(msg);
        } else {
            delete msg;
        }
    }
    
    void handleDNSQuery(cMessage* msg) {
        long src = SRC(msg);
        string qname = msg->par("qname").stringValue();
        bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
        bool isUDP = msg->hasPar("protocol") && 
                     string(msg->par("protocol").stringValue()) == "UDP";
        
        // Decrypt if encrypted
        if (isEncrypted && sharedKeys.find(src) != sharedKeys.end()) {
            qname = simpleDecrypt(qname, sharedKeys[src]);
        }
        
        EV_INFO << "DNS " << addr << " received query for '" << qname << "' from " << src;
        if (isEncrypted) EV_INFO << " (encrypted)";
        if (isUDP) EV_INFO << " (UDP)";
        EV_INFO << "\n";
        
        // Create response
        int responseKind = isUDP ? UDP_DATA : (msg->getKind() == TCP_DATA ? TCP_DATA : DNS_RESPONSE);
        auto *resp = mk("DNS_RESPONSE", responseKind, addr, src);
        resp->addPar("qname").setStringValue(qname.c_str());
        resp->addPar("answer").setLongValue(answer);
        
        // Encrypt response if we have shared key
        if (sharedKeys.find(src) != sharedKeys.end()) {
            string encryptedQname = simpleEncrypt(qname, sharedKeys[src]);
            resp->par("qname").setStringValue(encryptedQname.c_str());
            resp->addPar("encrypted").setBoolValue(true);
        }
        
        // Set priority based on request priority
        resp->par("priority").setLongValue(PRIORITY(msg));
        
        // For TCP, set sequence numbers
        if (responseKind == TCP_DATA) {
            auto it = tcpConnections.find(src);
            if (it != tcpConnections.end()) {
                resp->par("seq").setLongValue(it->second.sendSeq);
                resp->par("ack").setLongValue(it->second.recvSeq);
                it->second.sendSeq++;
            }
        }
        
        sendPacketOnGate(resp);
        EV_INFO << "DNS " << addr << " sent response to " << src << "\n";
        delete msg;
    }
    
    void finish() override {
        cancelAndDelete(rateLimitResetTimer);
        
        // Clean up transmission queue
        if (endTxEvent != nullptr) {
            cancelAndDelete(endTxEvent);
        }
        while (!txQueue.isEmpty()) {
            delete txQueue.pop();
        }
        
        while (!requestQueue.empty()) {
            delete requestQueue.top();
            requestQueue.pop();
        }
    }
};
Define_Module(DNS);