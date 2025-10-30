#include <omnetpp.h>
#include "helpers.h"
#include <map>
#include <sstream>
#include <queue>
using namespace omnetpp;
using namespace std;

class HTTP : public cSimpleModule {
  private:
    int addr = 0;
    
    // Security
    map<long, string> sharedKeys;
    string myPublicKey;
    string myPrivateKey;
    
    // TCP connections
    map<long, TCPConnection> tcpConnections;
    
    // SYN flood protection
    map<long, int> synCounts;
    map<long, simtime_t> synTimestamps;
    double synRateLimit;
    cMessage* synFloodCheckTimer;
    
    // Priority-based response queue
    priority_queue<cMessage*, vector<cMessage*>, MessagePriorityCompare> responseQueue;
    cMessage* sendQueueTimer;
    
    // Congestion control
    map<long, double> cwndMap;  // Per-connection congestion window
    map<long, double> ssthreshMap;
    
    // Transmission queue management
    cQueue txQueue;
    cMessage* endTxEvent;
    
  protected:
    void initialize() override { 
        addr = par("address"); 
        
        // Initialize security
        myPrivateKey = generateECDHPublicKey(addr);
        myPublicKey = generateECDHPublicKey(addr * 2);
        
        // SYN flood protection
        synRateLimit = par("synRateLimit").doubleValue();
        synFloodCheckTimer = new cMessage("synFloodCheck");
        scheduleAt(simTime() + 1.0, synFloodCheckTimer);
        
        // Queue processing
        sendQueueTimer = new cMessage("sendQueue");
        
        // Initialize transmission queue
        txQueue.setName("txQueue");
        endTxEvent = nullptr;
        
        EV_INFO << "HTTP server " << addr << " initialized\n";
    }

    void handleMessage(cMessage *msg) override {
        if (msg->isSelfMessage()) {
            handleSelfMessage(msg);
            return;
        }
        
        int kind = msg->getKind();
        
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
            case TCP_FIN:
                handleTCPFin(msg);
                break;
            case HTTP_GET:
                handleHTTPGet(msg);
                break;
            case UDP_DATA:
                handleUDPRequest(msg);
                break;
            default:
                EV_WARN << "HTTP unexpected kind=" << kind << "\n";
                delete msg;
        }
    }
    
    void handleSelfMessage(cMessage* msg) {
        if (msg == synFloodCheckTimer) {
            // Clear old SYN tracking entries
            simtime_t now = simTime();
            for (auto it = synTimestamps.begin(); it != synTimestamps.end(); ) {
                if (now - it->second > 60.0) {  // 60 second window
                    synCounts.erase(it->first);
                    it = synTimestamps.erase(it);
                } else {
                    ++it;
                }
            }
            scheduleAt(simTime() + 1.0, synFloodCheckTimer);
        } else if (msg == sendQueueTimer) {
            // Process queued responses
            if (!responseQueue.empty()) {
                cMessage* queued = responseQueue.top();
                responseQueue.pop();
                sendPacketOnGate(queued);
                
                if (!responseQueue.empty()) {
                    scheduleAt(simTime() + 0.001, sendQueueTimer);
                }
            }
        } else if (msg == endTxEvent) {
            // Transmission finished, send next packet if available
            endTxEvent = nullptr;
            if (!txQueue.isEmpty()) {
                cMessage* nextMsg = (cMessage*)txQueue.pop();
                startTransmission(nextMsg);
            }
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
            EV_INFO << "HTTP" << addr << " channel busy, queued packet " << msg->getName() << "\n";
        } else if (endTxEvent != nullptr) {
            // Already transmitting, queue the packet
            txQueue.insert(msg);
            EV_INFO << "HTTP" << addr << " transmission in progress, queued packet " << msg->getName() << "\n";
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
        EV_INFO << "HTTP" << addr << " started transmission of " << msg->getName() << ", finish at " << finishTime << "\n";
    }
    
    void handleKeyExchange(cMessage* msg) {
        long peerAddr = SRC(msg);
        string peerPublicKey = msg->par("publicKey").stringValue();
        
        // Compute shared secret
        string sharedSecret = computeSharedSecret(myPrivateKey, peerPublicKey);
        sharedKeys[peerAddr] = sharedSecret;
        
        // Send our public key back if needed
        if (sharedKeys.find(peerAddr) == sharedKeys.end() || sharedKeys[peerAddr].empty()) {
            auto* response = mk("KEY_EXCHANGE", KEY_EXCHANGE, addr, peerAddr);
            response->addPar("publicKey").setStringValue(myPublicKey.c_str());
            response->par("priority").setLongValue(PRIORITY_HIGH);
            sendPacketOnGate(response);
        }
        
        sharedKeys[peerAddr] = sharedSecret;
        EV_INFO << "HTTP " << addr << " completed key exchange with " << peerAddr << "\n";
        delete msg;
    }
    
    void handleTCPSyn(cMessage* msg) {
        long src = SRC(msg);
        long seq = SEQ(msg);
        
        // SYN flood protection using SYN cookies
        synCounts[src]++;
        synTimestamps[src] = simTime();
        
        // Check rate limit
        if (synCounts[src] > synRateLimit) {
            EV_WARN << "HTTP " << addr << " SYN flood detected from " << src 
                    << ", dropping SYN (count=" << synCounts[src] << ")\n";
            delete msg;
            return;
        }
        
        // Validate SYN cookie
        long cookie = msg->par("synCookie").longValue();
        if (!validateSYNCookie(cookie, src, addr, seq)) {
            EV_WARN << "HTTP " << addr << " invalid SYN cookie from " << src << "\n";
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
        
        // Create TCP connection state
        TCPConnection conn;
        conn.remoteAddr = src;
        conn.state = TCP_SYN_RECEIVED;
        conn.sendSeq = serverSeq + 1;
        conn.recvSeq = seq + 1;
        conn.cwnd = 1.0;
        conn.ssthresh = 64.0;
        tcpConnections[src] = conn;
        
        cwndMap[src] = 1.0;
        ssthreshMap[src] = 64.0;
        
        EV_INFO << "HTTP " << addr << " sent SYN-ACK to " << src << "\n";
        delete msg;
    }
    
    void handleTCPAck(cMessage* msg) {
        long src = SRC(msg);
        
        auto it = tcpConnections.find(src);
        if (it != tcpConnections.end()) {
            if (it->second.state == TCP_SYN_RECEIVED) {
                it->second.state = TCP_ESTABLISHED;
                EV_INFO << "HTTP " << addr << " TCP connection established with " << src << "\n";
            }
            
            // Update congestion window (AIMD)
            if (cwndMap[src] < ssthreshMap[src]) {
                cwndMap[src] *= 2;  // Slow start
            } else {
                cwndMap[src] += 1.0 / cwndMap[src];  // Congestion avoidance
            }
            
            EV_INFO << "HTTP " << addr << " received ACK from " << src 
                    << ", cwnd=" << cwndMap[src] << "\n";
        }
        delete msg;
    }
    
    void handleTCPData(cMessage* msg) {
        // HTTP request received over TCP
        if (msg->hasPar("path")) {
            handleHTTPGet(msg);
        } else {
            long src = SRC(msg);
            long seq = SEQ(msg);
            
            // Send ACK
            auto* ack = mk("TCP_ACK", TCP_ACK, addr, src);
            ack->par("ack").setLongValue(seq + 1);
            ack->par("priority").setLongValue(PRIORITY_HIGH);
            sendPacketOnGate(ack);
            
            delete msg;
        }
    }
    
    void handleTCPFin(cMessage* msg) {
        long src = SRC(msg);
        
        // Send FIN-ACK
        auto* finAck = mk("TCP_FIN", TCP_FIN, addr, src);
        finAck->par("priority").setLongValue(PRIORITY_NORMAL);
        sendPacketOnGate(finAck);
        
        // Clean up connection state
        tcpConnections.erase(src);
        cwndMap.erase(src);
        ssthreshMap.erase(src);
        
        EV_INFO << "HTTP " << addr << " closed TCP connection with " << src << "\n";
        delete msg;
    }
    
    void handleHTTPGet(cMessage* msg) {
        long src = SRC(msg);
        string path = msg->par("path").stringValue();
        bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
        int priority = PRIORITY(msg);
        
        // Decrypt if encrypted
        if (isEncrypted && sharedKeys.find(src) != sharedKeys.end()) {
            path = simpleDecrypt(path, sharedKeys[src]);
        }
        
        EV_INFO << "HTTP " << addr << " received GET request for '" << path 
                << "' from " << src;
        if (isEncrypted) EV_INFO << " (encrypted)";
        EV_INFO << "\n";
        
        // Prepare response
        int responseKind = (msg->getKind() == TCP_DATA) ? TCP_DATA : HTTP_RESPONSE;
        auto *resp = mk("HTTP_RESPONSE", responseKind, addr, src);
        resp->addPar("bytes").setLongValue(par("pageSizeBytes").intValue());
        resp->par("priority").setLongValue(priority);
        
        // Encrypt response if we have shared key
        if (sharedKeys.find(src) != sharedKeys.end()) {
            string data = "HTTP_DATA";  // Placeholder
            string encrypted = simpleEncrypt(data, sharedKeys[src]);
            resp->addPar("encData").setStringValue(encrypted.c_str());
            resp->addPar("encrypted").setBoolValue(true);
        }
        
        // Set TCP sequence numbers if applicable
        if (responseKind == TCP_DATA) {
            auto it = tcpConnections.find(src);
            if (it != tcpConnections.end()) {
                resp->par("seq").setLongValue(it->second.sendSeq);
                resp->par("ack").setLongValue(it->second.recvSeq);
                it->second.sendSeq++;
            }
        }
        
        // Priority-based sending
        double serviceTime = par("serviceTime").doubleValue();
        if (priority >= PRIORITY_HIGH) {
            // High priority: send immediately with reduced service time
            sendDelayed(resp, SimTime(serviceTime * 0.5), "ppp$o");
            EV_INFO << "HTTP " << addr << " sending high-priority response immediately\n";
        } else {
            // Normal/low priority: queue and send with full service time
            responseQueue.push(resp);
            if (!sendQueueTimer->isScheduled()) {
                scheduleAt(simTime() + serviceTime, sendQueueTimer);
            }
            EV_INFO << "HTTP " << addr << " queued response (priority=" << priority << ")\n";
        }
        
        delete msg;
    }
    
    void handleUDPRequest(cMessage* msg) {
        // Handle UDP-based HTTP request (low latency)
        if (msg->hasPar("path")) {
            long src = SRC(msg);
            string path = msg->par("path").stringValue();
            bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
            
            // Decrypt if encrypted
            if (isEncrypted && sharedKeys.find(src) != sharedKeys.end()) {
                path = simpleDecrypt(path, sharedKeys[src]);
            }
            
            EV_INFO << "HTTP " << addr << " received UDP GET for '" << path << "'\n";
            
            // Quick UDP response (no reliability, lower latency)
            auto* resp = mk("HTTP_RESPONSE", UDP_DATA, addr, src);
            resp->addPar("bytes").setLongValue(par("pageSizeBytes").intValue());
            resp->par("priority").setLongValue(PRIORITY(msg));
            
            // Encrypt if key available
            if (sharedKeys.find(src) != sharedKeys.end()) {
                string data = "HTTP_UDP_DATA";
                string encrypted = simpleEncrypt(data, sharedKeys[src]);
                resp->addPar("encData").setStringValue(encrypted.c_str());
                resp->addPar("encrypted").setBoolValue(true);
            }
            
            // UDP response sent with minimal delay
            sendDelayed(resp, SimTime(par("serviceTime").doubleValue() * 0.3), "ppp$o");
            EV_INFO << "HTTP " << addr << " sent UDP response\n";
        }
        delete msg;
    }
    
    void finish() override {
        cancelAndDelete(synFloodCheckTimer);
        cancelAndDelete(sendQueueTimer);
        
        // Clean up transmission queue
        if (endTxEvent != nullptr) {
            cancelAndDelete(endTxEvent);
        }
        while (!txQueue.isEmpty()) {
            delete txQueue.pop();
        }
        
        while (!responseQueue.empty()) {
            delete responseQueue.top();
            responseQueue.pop();
        }
    }
};
Define_Module(HTTP);
