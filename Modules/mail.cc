#include <omnetpp.h>
#include "helpers.h"
#include <map>
#include <queue>
using namespace omnetpp;
using namespace std;

class MailServer : public cSimpleModule {
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
    
    // Mail queue
    priority_queue<cMessage*, vector<cMessage*>, MessagePriorityCompare> mailQueue;
    cMessage* processMailTimer;
    
    // Congestion control
    map<long, double> cwndMap;
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
        
        // Mail processing
        processMailTimer = new cMessage("processMail");
        
        // Initialize transmission queue
        txQueue.setName("txQueue");
        endTxEvent = nullptr;
        
        EV_INFO << "Mail server " << addr << " initialized\n";
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
                handleMailRequest(msg);
                break;
            case TCP_FIN:
                handleTCPFin(msg);
                break;
            default:
                EV_WARN << "MailServer " << addr << " unexpected kind=" << kind << "\n";
                delete msg;
        }
    }
    
    void handleSelfMessage(cMessage* msg) {
        if (msg == synFloodCheckTimer) {
            // Clear old SYN tracking entries
            simtime_t now = simTime();
            for (auto it = synTimestamps.begin(); it != synTimestamps.end(); ) {
                if (now - it->second > 60.0) {
                    synCounts.erase(it->first);
                    it = synTimestamps.erase(it);
                } else {
                    ++it;
                }
            }
            scheduleAt(simTime() + 1.0, synFloodCheckTimer);
        } else if (msg == processMailTimer) {
            // Process queued mail
            if (!mailQueue.empty()) {
                cMessage* queued = mailQueue.top();
                mailQueue.pop();
                sendPacketOnGate(queued);
                
                if (!mailQueue.empty()) {
                    scheduleAt(simTime() + 0.002, processMailTimer);
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
            EV_INFO << "Mail" << addr << " channel busy, queued packet " << msg->getName() << "\n";
        } else if (endTxEvent != nullptr) {
            // Already transmitting, queue the packet
            txQueue.insert(msg);
            EV_INFO << "Mail" << addr << " transmission in progress, queued packet " << msg->getName() << "\n";
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
        EV_INFO << "Mail" << addr << " started transmission of " << msg->getName() << ", finish at " << finishTime << "\n";
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
        EV_INFO << "MailServer " << addr << " completed key exchange with " << peerAddr << "\n";
        delete msg;
    }
    
    void handleTCPSyn(cMessage* msg) {
        long src = SRC(msg);
        long seq = SEQ(msg);
        
        // SYN flood protection
        synCounts[src]++;
        synTimestamps[src] = simTime();
        
        if (synCounts[src] > synRateLimit) {
            EV_WARN << "MailServer " << addr << " SYN flood from " << src << "\n";
            delete msg;
            return;
        }
        
        // Validate SYN cookie
        long cookie = msg->par("synCookie").longValue();
        if (!validateSYNCookie(cookie, src, addr, seq)) {
            EV_WARN << "MailServer " << addr << " invalid SYN cookie from " << src << "\n";
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
        conn.cwnd = 1.0;
        conn.ssthresh = 64.0;
        tcpConnections[src] = conn;
        
        cwndMap[src] = 1.0;
        ssthreshMap[src] = 64.0;
        
        EV_INFO << "MailServer " << addr << " sent SYN-ACK to " << src << "\n";
        delete msg;
    }
    
    void handleTCPAck(cMessage* msg) {
        long src = SRC(msg);
        
        auto it = tcpConnections.find(src);
        if (it != tcpConnections.end()) {
            if (it->second.state == TCP_SYN_RECEIVED) {
                it->second.state = TCP_ESTABLISHED;
                EV_INFO << "MailServer " << addr << " connection established with " << src << "\n";
            }
            
            // Update congestion window
            if (cwndMap[src] < ssthreshMap[src]) {
                cwndMap[src] *= 2;
            } else {
                cwndMap[src] += 1.0 / cwndMap[src];
            }
        }
        delete msg;
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
        
        EV_INFO << "MailServer " << addr << " closed connection with " << src << "\n";
        delete msg;
    }
    
    void handleMailRequest(cMessage* msg) {
        long src = SRC(msg);
        bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
        int priority = PRIORITY(msg);
        
        EV_INFO << "MailServer " << addr << " received mail request from " << src;
        if (isEncrypted) EV_INFO << " (encrypted)";
        EV_INFO << "\n";
        
        // Prepare mail response
        auto* resp = mk("MAIL_RESPONSE", TCP_DATA, addr, src);
        resp->addPar("bytes").setLongValue(par("mailSizeBytes").intValue());
        resp->par("priority").setLongValue(priority);
        
        // Encrypt if we have shared key
        if (sharedKeys.find(src) != sharedKeys.end()) {
            string mailData = "MAIL_CONTENT";
            string encrypted = simpleEncrypt(mailData, sharedKeys[src]);
            resp->addPar("encData").setStringValue(encrypted.c_str());
            resp->addPar("encrypted").setBoolValue(true);
        }
        
        // Set TCP sequence numbers
        auto it = tcpConnections.find(src);
        if (it != tcpConnections.end()) {
            resp->par("seq").setLongValue(it->second.sendSeq);
            resp->par("ack").setLongValue(it->second.recvSeq);
            it->second.sendSeq++;
        }
        
        // Priority-based sending
        double serviceTime = par("serviceTime").doubleValue();
        if (priority >= PRIORITY_HIGH) {
            sendDelayed(resp, SimTime(serviceTime * 0.7), "ppp$o");
        } else {
            mailQueue.push(resp);
            if (!processMailTimer->isScheduled()) {
                scheduleAt(simTime() + serviceTime, processMailTimer);
            }
        }
        
        delete msg;
    }
    
    void finish() override {
        cancelAndDelete(synFloodCheckTimer);
        cancelAndDelete(processMailTimer);
        
        // Clean up transmission queue
        if (endTxEvent != nullptr) {
            cancelAndDelete(endTxEvent);
        }
        while (!txQueue.isEmpty()) {
            delete txQueue.pop();
        }
        
        while (!mailQueue.empty()) {
            delete mailQueue.top();
            mailQueue.pop();
        }
    }
};
Define_Module(MailServer);
