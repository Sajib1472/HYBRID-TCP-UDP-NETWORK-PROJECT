#include <omnetpp.h>
#include "helpers.h"
#include <map>
#include <queue>
using namespace omnetpp;
using namespace std;

class DatabaseServer : public cSimpleModule {
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
    
    // Query queue with priority
    priority_queue<cMessage*, vector<cMessage*>, MessagePriorityCompare> queryQueue;
    cMessage* processQueryTimer;
    
    // Transaction management
    map<long, int> activeTransactions;  // client -> transaction count
    
    // Congestion control
    map<long, double> cwndMap;
    
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
        
        // Query processing
        processQueryTimer = new cMessage("processQuery");
        
        // Initialize transmission queue
        txQueue.setName("txQueue");
        endTxEvent = nullptr;
        
        EV_INFO << "Database server " << addr << " initialized\n";
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
                handleDatabaseQuery(msg);
                break;
            case TCP_FIN:
                handleTCPFin(msg);
                break;
            default:
                EV_WARN << "DatabaseServer " << addr << " unexpected kind=" << kind << "\n";
                delete msg;
        }
    }
    
    void handleSelfMessage(cMessage* msg) {
        if (msg == synFloodCheckTimer) {
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
        } else if (msg == processQueryTimer) {
            if (!queryQueue.empty()) {
                cMessage* query = queryQueue.top();
                queryQueue.pop();
                sendPacketOnGate(query);
                
                if (!queryQueue.empty()) {
                    scheduleAt(simTime() + 0.001, processQueryTimer);
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
            EV_INFO << "DB" << addr << " channel busy, queued packet " << msg->getName() << "\n";
        } else if (endTxEvent != nullptr) {
            // Already transmitting, queue the packet
            txQueue.insert(msg);
            EV_INFO << "DB" << addr << " transmission in progress, queued packet " << msg->getName() << "\n";
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
        EV_INFO << "DB" << addr << " started transmission of " << msg->getName() << ", finish at " << finishTime << "\n";
    }
    
    void handleKeyExchange(cMessage* msg) {
        long peerAddr = SRC(msg);
        string peerPublicKey = msg->par("publicKey").stringValue();
        
        string sharedSecret = computeSharedSecret(myPrivateKey, peerPublicKey);
        sharedKeys[peerAddr] = sharedSecret;
        
        if (sharedKeys.find(peerAddr) == sharedKeys.end() || sharedKeys[peerAddr].empty()) {
            auto* response = mk("KEY_EXCHANGE", KEY_EXCHANGE, addr, peerAddr);
            response->addPar("publicKey").setStringValue(myPublicKey.c_str());
            response->par("priority").setLongValue(PRIORITY_HIGH);
            sendPacketOnGate(response);
        }
        
        sharedKeys[peerAddr] = sharedSecret;
        EV_INFO << "DatabaseServer " << addr << " key exchange with " << peerAddr << "\n";
        delete msg;
    }
    
    void handleTCPSyn(cMessage* msg) {
        long src = SRC(msg);
        long seq = SEQ(msg);
        
        synCounts[src]++;
        synTimestamps[src] = simTime();
        
        if (synCounts[src] > synRateLimit) {
            EV_WARN << "DatabaseServer " << addr << " SYN flood from " << src << "\n";
            delete msg;
            return;
        }
        
        long cookie = msg->par("synCookie").longValue();
        if (!validateSYNCookie(cookie, src, addr, seq)) {
            delete msg;
            return;
        }
        
        long serverSeq = intuniform(1000, 9999);
        auto* synAck = mk("TCP_SYN_ACK", TCP_SYN_ACK, addr, src);
        synAck->par("seq").setLongValue(serverSeq);
        synAck->par("ack").setLongValue(seq + 1);
        synAck->par("priority").setLongValue(PRIORITY_HIGH);
        synAck->addPar("synCookie").setLongValue(generateSYNCookie(addr, src, serverSeq));
        sendPacketOnGate(synAck);
        
        TCPConnection conn;
        conn.remoteAddr = src;
        conn.state = TCP_SYN_RECEIVED;
        conn.sendSeq = serverSeq + 1;
        conn.recvSeq = seq + 1;
        conn.cwnd = 2.0;  // Database: higher initial window
        conn.ssthresh = 128.0;
        tcpConnections[src] = conn;
        
        cwndMap[src] = 2.0;
        
        EV_INFO << "DatabaseServer " << addr << " SYN-ACK to " << src << "\n";
        delete msg;
    }
    
    void handleTCPAck(cMessage* msg) {
        long src = SRC(msg);
        
        auto it = tcpConnections.find(src);
        if (it != tcpConnections.end()) {
            if (it->second.state == TCP_SYN_RECEIVED) {
                it->second.state = TCP_ESTABLISHED;
                EV_INFO << "DatabaseServer " << addr << " connection established with " << src << "\n";
            }
            
            // Update congestion window
            cwndMap[src] += 1.0 / cwndMap[src];
        }
        delete msg;
    }
    
    void handleDatabaseQuery(cMessage* msg) {
        long src = SRC(msg);
        bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
        int priority = PRIORITY(msg);
        
        // Track active transactions
        activeTransactions[src]++;
        
        EV_INFO << "DatabaseServer " << addr << " query from " << src;
        if (isEncrypted) EV_INFO << " (encrypted)";
        EV_INFO << " [transaction #" << activeTransactions[src] << "]\n";
        
        // Prepare database response
        auto* resp = mk("DB_RESPONSE", TCP_DATA, addr, src);
        resp->addPar("bytes").setLongValue(par("responseBytes").intValue());
        resp->par("priority").setLongValue(priority);
        resp->addPar("transactionId").setLongValue(activeTransactions[src]);
        
        // Encrypt response if we have shared key
        if (sharedKeys.find(src) != sharedKeys.end()) {
            string dbData = "DATABASE_QUERY_RESULT";
            string encrypted = simpleEncrypt(dbData, sharedKeys[src]);
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
        
        // Priority-based query processing
        double queryTime = par("queryTime").doubleValue();
        if (priority >= PRIORITY_HIGH) {
            // Critical queries: immediate processing
            scheduleAt(simTime() + (queryTime * 0.5), resp);
            sendPacketOnGate(resp);
            EV_INFO << "DatabaseServer " << addr << " high-priority query\n";
        } else {
            // Normal queries: queue
            queryQueue.push(resp);
            if (!processQueryTimer->isScheduled()) {
                scheduleAt(simTime() + queryTime, processQueryTimer);
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
        activeTransactions.erase(src);
        
        EV_INFO << "DatabaseServer " << addr << " closed connection with " << src << "\n";
        delete msg;
    }
    
    void finish() override {
        cancelAndDelete(synFloodCheckTimer);
        cancelAndDelete(processQueryTimer);
        
        // Clean up transmission queue
        if (endTxEvent != nullptr) {
            cancelAndDelete(endTxEvent);
        }
        while (!txQueue.isEmpty()) {
            delete txQueue.pop();
        }
        
        while (!queryQueue.empty()) {
            delete queryQueue.top();
            queryQueue.pop();
        }
    }
};
Define_Module(DatabaseServer);
