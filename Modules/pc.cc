#include <omnetpp.h>
#include "helpers.h"
#include <map>
#include <sstream>
#include <queue>
using namespace omnetpp;
using namespace std;

class PC : public cSimpleModule {
  private:
    int addr = 0;
    int dnsAddr = 2;
    string qname;
    cMessage *startEvt = nullptr;
    
    // TCP/UDP Hybrid Protocol
    string protocol;  // "TCP" or "UDP" or "AUTO"
    map<long, TCPConnection> tcpConnections;
    
    // Security (ECDH + AES)
    string myPublicKey;
    string myPrivateKey;
    map<long, string> sharedKeys;
    
    // Congestion control
    double cwnd;           // Congestion window
    double ssthresh;       // Slow start threshold
    int dupAckCount;
    
    // Traffic management
    priority_queue<cMessage*, vector<cMessage*>, MessagePriorityCompare> sendQueue;
    
    // Transmission queue management (to prevent channel busy errors)
    cQueue txQueue;
    cMessage* endTxEvent;
    
    // Timers
    cMessage* retransmitTimer;
    cMessage* congestionTimer;

  protected:
    void initialize() override {
        addr    = par("address");
        dnsAddr = par("dnsAddr");
        qname   = par("dnsQuery").stdstringValue();
        protocol = par("protocol").stdstringValue();
        
        // Initialize security
        myPrivateKey = generateECDHPublicKey(addr);
        myPublicKey = generateECDHPublicKey(addr * 2);
        
        // Initialize congestion control
        cwnd = 1.0;
        ssthresh = 64.0;
        dupAckCount = 0;
        
        // Initialize timers
        retransmitTimer = new cMessage("retransmit");
        congestionTimer = new cMessage("congestion");
        
        // Initialize transmission queue
        txQueue.setName("txQueue");
        endTxEvent = nullptr;
        
        startEvt = new cMessage("start");
        scheduleAt(simTime() + SimTime(par("startAt").doubleValue()), startEvt);
        EV_INFO << "PC" << addr << " initialized with protocol=" << protocol << "\n";
    }

    void handleMessage(cMessage *msg) override {
        if (msg->isSelfMessage()) {
            handleSelfMessage(msg);
            return;
        }

        int kind = msg->getKind();
        
        switch (kind) {
            case DNS_RESPONSE: {
                handleDNSResponse(msg);
                break;
            }
            case HTTP_RESPONSE: {
                handleHTTPResponse(msg);
                break;
            }
            case DB_RESPONSE: {
                handleDBResponse(msg);
                break;
            }
            case TCP_SYN_ACK: {
                handleTCPSynAck(msg);
                break;
            }
            case TCP_ACK: {
                handleTCPAck(msg);
                break;
            }
            case TCP_DATA: {
                handleTCPData(msg);
                break;
            }
            case TCP_FIN: {
                handleTCPFin(msg);
                break;
            }
            case UDP_DATA: {
                handleUDPData(msg);
                break;
            }
            case KEY_EXCHANGE: {
                handleKeyExchange(msg);
                break;
            }
            case ENCRYPTED_DATA: {
                handleEncryptedData(msg);
                break;
            }
            default:
                EV_WARN << "PC" << addr << " unexpected kind=" << kind << "\n";
                delete msg;
        }
    }
    
    void handleSelfMessage(cMessage* msg) {
        if (msg == startEvt) {
            // Step 1: Initiate key exchange
            initiateKeyExchange(dnsAddr);
            
            // Step 2: Send DNS query (choose protocol based on setting)
            if (protocol == "UDP" || protocol == "AUTO") {
                sendDNSQueryUDP();
            } else {
                sendDNSQueryTCP();
            }
        } else if (msg == retransmitTimer) {
            handleRetransmit();
        } else if (msg == congestionTimer) {
            handleCongestionTimeout();
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
            EV_INFO << "PC" << addr << " channel busy, queued packet " << msg->getName() << "\n";
        } else if (endTxEvent != nullptr) {
            // Already transmitting, queue the packet
            txQueue.insert(msg);
            EV_INFO << "PC" << addr << " transmission in progress, queued packet " << msg->getName() << "\n";
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
        EV_INFO << "PC" << addr << " started transmission of " << msg->getName() << ", finish at " << finishTime << "\n";
    }
    
    void initiateKeyExchange(long peerAddr) {
        auto* keyMsg = mk("KEY_EXCHANGE", KEY_EXCHANGE, addr, peerAddr);
        keyMsg->addPar("publicKey").setStringValue(myPublicKey.c_str());
        keyMsg->par("priority").setLongValue(PRIORITY_HIGH);
        sendPacketOnGate(keyMsg);
        EV_INFO << "PC" << addr << " initiated key exchange with " << peerAddr << "\n";
    }
    
    void handleKeyExchange(cMessage* msg) {
        long peerAddr = SRC(msg);
        string peerPublicKey = msg->par("publicKey").stringValue();
        
        // Compute shared secret
        string sharedSecret = computeSharedSecret(myPrivateKey, peerPublicKey);
        sharedKeys[peerAddr] = sharedSecret;
        
        // Send our public key back
        auto* response = mk("KEY_EXCHANGE", KEY_EXCHANGE, addr, peerAddr);
        response->addPar("publicKey").setStringValue(myPublicKey.c_str());
        response->par("priority").setLongValue(PRIORITY_HIGH);
        sendPacketOnGate(response);
        
        EV_INFO << "PC" << addr << " completed key exchange with " << peerAddr << "\n";
        delete msg;
    }
    
    void sendDNSQueryTCP() {
        // Initiate TCP connection with three-way handshake
        long seq = intuniform(1000, 9999);
        
        auto* syn = mk("TCP_SYN", TCP_SYN, addr, dnsAddr);
        syn->par("seq").setLongValue(seq);
        syn->par("priority").setLongValue(PRIORITY_HIGH);
        syn->addPar("synCookie").setLongValue(generateSYNCookie(addr, dnsAddr, seq));
        
        TCPConnection conn;
        conn.remoteAddr = dnsAddr;
        conn.state = TCP_SYN_SENT;
        conn.sendSeq = seq + 1;
        conn.lastSent = simTime();
        tcpConnections[dnsAddr] = conn;
        
        sendPacketOnGate(syn);
        EV_INFO << "PC" << addr << " sent TCP SYN to DNS server " << dnsAddr << "\n";
        
        // Set retransmit timer
        if (!retransmitTimer->isScheduled()) {
            scheduleAt(simTime() + 3.0, retransmitTimer);
        }
    }
    
    void sendDNSQueryUDP() {
        // Send DNS query via UDP (low latency)
        auto* query = mk("DNS_QUERY", DNS_QUERY, addr, dnsAddr);
        query->addPar("qname").setStringValue(qname.c_str());
        query->par("priority").setLongValue(PRIORITY_HIGH);
        query->addPar("protocol").setStringValue("UDP");
        
        // Encrypt if key is available
        if (sharedKeys.find(dnsAddr) != sharedKeys.end()) {
            string encrypted = simpleEncrypt(qname, sharedKeys[dnsAddr]);
            query->par("qname").setStringValue(encrypted.c_str());
            query->addPar("encrypted").setBoolValue(true);
        }
        
        sendPacketOnGate(query);
        EV_INFO << "PC" << addr << " sent UDP DNS query for " << qname << "\n";
    }
    
    void handleTCPSynAck(cMessage* msg) {
        long peerAddr = SRC(msg);
        long seq = SEQ(msg);
        
        auto it = tcpConnections.find(peerAddr);
        if (it != tcpConnections.end() && it->second.state == TCP_SYN_SENT) {
            // Validate SYN cookie
            long cookie = msg->par("synCookie").longValue();
            if (validateSYNCookie(cookie, peerAddr, addr, seq)) {
                // Complete three-way handshake
                auto* ack = mk("TCP_ACK", TCP_ACK, addr, peerAddr);
                ack->par("seq").setLongValue(it->second.sendSeq);
                ack->par("ack").setLongValue(seq + 1);
                ack->par("priority").setLongValue(PRIORITY_HIGH);
                sendPacketOnGate(ack);
                
                it->second.state = TCP_ESTABLISHED;
                it->second.recvSeq = seq + 1;
                EV_INFO << "PC" << addr << " TCP connection established with " << peerAddr << "\n";
                
                // Determine if this is DNS or HTTP connection and send appropriate data
                if (peerAddr == dnsAddr) {
                    // Now send actual DNS query over TCP
                    sendDNSDataTCP(peerAddr);
                } else if (peerAddr == 601) {
                    // Send DB query over established TCP connection
                    sendDBQueryTCP(peerAddr);
                } else {
                    // Send HTTP GET request over established TCP connection
                    sendHTTPDataTCP(peerAddr);
                }
            } else {
                EV_WARN << "PC" << addr << " invalid SYN cookie from " << peerAddr << "\n";
            }
        }
        delete msg;
    }
    
    void sendHTTPDataTCP(long httpAddr) {
        auto* get = mk("HTTP_GET", TCP_DATA, addr, httpAddr);
        get->addPar("path").setStringValue("/");
        get->par("seq").setLongValue(tcpConnections[httpAddr].sendSeq);
        get->par("priority").setLongValue(PRIORITY_NORMAL);
        
        // Encrypt if key available
        if (sharedKeys.find(httpAddr) != sharedKeys.end()) {
            string encrypted = simpleEncrypt("/", sharedKeys[httpAddr]);
            get->par("path").setStringValue(encrypted.c_str());
            get->addPar("encrypted").setBoolValue(true);
        }
        
        sendPacketOnGate(get);
        tcpConnections[httpAddr].sendSeq++;
        EV_INFO << "PC" << addr << " sent TCP HTTP GET request\n";
    }
    
    void sendDNSDataTCP(long peerAddr) {
        auto* data = mk("DNS_QUERY", TCP_DATA, addr, peerAddr);
        data->addPar("qname").setStringValue(qname.c_str());
        data->par("seq").setLongValue(tcpConnections[peerAddr].sendSeq);
        data->par("priority").setLongValue(PRIORITY_NORMAL);
        
        // Encrypt if key available
        if (sharedKeys.find(peerAddr) != sharedKeys.end()) {
            string encrypted = simpleEncrypt(qname, sharedKeys[peerAddr]);
            data->par("qname").setStringValue(encrypted.c_str());
            data->addPar("encrypted").setBoolValue(true);
        }
        
        sendPacketOnGate(data);
        tcpConnections[peerAddr].sendSeq++;
        EV_INFO << "PC" << addr << " sent TCP DNS query\n";
    }
    
    void sendDBQueryTCP(long dbAddr) {
        auto* query = mk("DB_QUERY", TCP_DATA, addr, dbAddr);
        query->addPar("query").setStringValue("SELECT * FROM users");
        query->par("seq").setLongValue(tcpConnections[dbAddr].sendSeq);
        query->par("priority").setLongValue(PRIORITY_NORMAL);
        
        // Encrypt if key available
        if (sharedKeys.find(dbAddr) != sharedKeys.end()) {
            string encrypted = simpleEncrypt("SELECT * FROM users", sharedKeys[dbAddr]);
            query->par("query").setStringValue(encrypted.c_str());
            query->addPar("encrypted").setBoolValue(true);
        }
        
        sendPacketOnGate(query);
        tcpConnections[dbAddr].sendSeq++;
        EV_INFO << "PC" << addr << " sent TCP DB query\n";
    }
    
    void handleTCPAck(cMessage* msg) {
        // Update congestion window (simplified AIMD)
        if (cwnd < ssthresh) {
            cwnd *= 2;  // Slow start
        } else {
            cwnd += 1.0 / cwnd;  // Congestion avoidance
        }
        
        dupAckCount = 0;
        EV_INFO << "PC" << addr << " received ACK, cwnd=" << cwnd << "\n";
        delete msg;
    }
    
    void handleTCPData(cMessage* msg) {
        // Receive data, send ACK
        long peerAddr = SRC(msg);
        long seq = SEQ(msg);
        
        // Check if this is HTTP response data
        if (msg->hasPar("bytes")) {
            long bytes = msg->par("bytes").longValue();
            bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
            
            EV_INFO << "PC" << addr << " received TCP HTTP response: " << bytes << " bytes";
            if (isEncrypted) {
                EV_INFO << " (encrypted)";
                
                // Decrypt if we have the key
                if (msg->hasPar("encData") && sharedKeys.find(peerAddr) != sharedKeys.end()) {
                    string encData = msg->par("encData").stringValue();
                    string decrypted = simpleDecrypt(encData, sharedKeys[peerAddr]);
                    EV_INFO << ", decrypted";
                }
            }
            EV_INFO << "\n";
            
            // After receiving HTTP response, initiate DB query
            if (tcpConnections.find(601) == tcpConnections.end()) {
                // Start TCP connection to DB server
                sendDBRequestTCP(601);
            }
        } else {
            EV_INFO << "PC" << addr << " received TCP data from " << peerAddr << "\n";
        }
        
        auto* ack = mk("TCP_ACK", TCP_ACK, addr, peerAddr);
        ack->par("ack").setLongValue(seq + 1);
        ack->par("priority").setLongValue(PRIORITY_HIGH);
        sendPacketOnGate(ack);
        
        EV_INFO << "PC" << addr << " sent ACK for TCP data\n";
        delete msg;
    }
    
    void handleTCPFin(cMessage* msg) {
        long peerAddr = SRC(msg);
        
        // Send FIN-ACK
        auto* finAck = mk("TCP_FIN", TCP_FIN, addr, peerAddr);
        finAck->par("priority").setLongValue(PRIORITY_NORMAL);
        sendPacketOnGate(finAck);
        
        tcpConnections[peerAddr].state = TCP_CLOSED;
        EV_INFO << "PC" << addr << " closed TCP connection with " << peerAddr << "\n";
        delete msg;
    }
    
    void handleUDPData(cMessage* msg) {
        EV_INFO << "PC" << addr << " received UDP data\n";
        delete msg;
    }
    
    void handleEncryptedData(cMessage* msg) {
        long peerAddr = SRC(msg);
        string encData = msg->par("encData").stringValue();
        
        if (sharedKeys.find(peerAddr) != sharedKeys.end()) {
            string decrypted = simpleDecrypt(encData, sharedKeys[peerAddr]);
            EV_INFO << "PC" << addr << " decrypted data from " << peerAddr << "\n";
        }
        delete msg;
    }
    
    void handleDNSResponse(cMessage* msg) {
        long httpAddr = msg->par("answer").longValue();
        bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
        
        string qnameResult = msg->par("qname").stringValue();
        if (isEncrypted && sharedKeys.find(SRC(msg)) != sharedKeys.end()) {
            qnameResult = simpleDecrypt(qnameResult, sharedKeys[SRC(msg)]);
        }
        
        EV_INFO << "PC" << addr << " DNS: " << qnameResult << " -> " << httpAddr << "\n";
        
        // Initiate key exchange with HTTP server
        initiateKeyExchange(httpAddr);
        
        // Also initiate key exchange with DB server (address 601)
        initiateKeyExchange(601);
        
        // Send HTTP request (choose protocol based on traffic type)
        if (protocol == "UDP") {
            sendHTTPRequestUDP(httpAddr);
        } else {
            sendHTTPRequestTCP(httpAddr);
        }
        
        delete msg;
    }
    
    void sendHTTPRequestTCP(long httpAddr) {
        // Initiate TCP connection first
        long seq = intuniform(1000, 9999);
        
        auto* syn = mk("TCP_SYN", TCP_SYN, addr, httpAddr);
        syn->par("seq").setLongValue(seq);
        syn->par("priority").setLongValue(PRIORITY_NORMAL);
        syn->addPar("synCookie").setLongValue(generateSYNCookie(addr, httpAddr, seq));
        
        TCPConnection conn;
        conn.remoteAddr = httpAddr;
        conn.state = TCP_SYN_SENT;
        conn.sendSeq = seq + 1;
        conn.lastSent = simTime();
        tcpConnections[httpAddr] = conn;
        
        sendPacketOnGate(syn);
        EV_INFO << "PC" << addr << " initiating TCP connection to HTTP server\n";
    }
    
    void sendDBRequestTCP(long dbAddr) {
        // Initiate TCP connection to database
        long seq = intuniform(1000, 9999);
        
        auto* syn = mk("TCP_SYN", TCP_SYN, addr, dbAddr);
        syn->par("seq").setLongValue(seq);
        syn->par("priority").setLongValue(PRIORITY_NORMAL);
        syn->addPar("synCookie").setLongValue(generateSYNCookie(addr, dbAddr, seq));
        
        TCPConnection conn;
        conn.remoteAddr = dbAddr;
        conn.state = TCP_SYN_SENT;
        conn.sendSeq = seq + 1;
        conn.lastSent = simTime();
        tcpConnections[dbAddr] = conn;
        
        sendPacketOnGate(syn);
        EV_INFO << "PC" << addr << " initiating TCP connection to DB server\n";
    }
    
    void sendHTTPRequestUDP(long httpAddr) {
        auto* get = mk("HTTP_GET", UDP_DATA, addr, httpAddr);
        get->addPar("path").setStringValue("/");
        get->par("priority").setLongValue(PRIORITY_NORMAL);
        
        // Encrypt if key available
        if (sharedKeys.find(httpAddr) != sharedKeys.end()) {
            string encrypted = simpleEncrypt("/", sharedKeys[httpAddr]);
            get->par("path").setStringValue(encrypted.c_str());
            get->addPar("encrypted").setBoolValue(true);
        }
        
        sendPacketOnGate(get);
        EV_INFO << "PC" << addr << " sent UDP HTTP GET request\n";
    }
    
    void handleHTTPResponse(cMessage* msg) {
        long bytes = msg->par("bytes").longValue();
        bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
        
        EV_INFO << "PC" << addr << " received HTTP response: " << bytes << " bytes";
        if (isEncrypted) {
            EV_INFO << " (encrypted)";
        }
        EV_INFO << "\n";
        
        delete msg;
    }
    
    void handleDBResponse(cMessage* msg) {
        long bytes = msg->par("bytes").longValue();
        bool isEncrypted = msg->hasPar("encrypted") && msg->par("encrypted").boolValue();
        string result = msg->par("result").stringValue();
        
        // Decrypt if encrypted
        if (isEncrypted && sharedKeys.find(SRC(msg)) != sharedKeys.end()) {
            result = simpleDecrypt(result, sharedKeys[SRC(msg)]);
        }
        
        EV_INFO << "PC" << addr << " received DB response: " << bytes << " bytes";
        if (isEncrypted) {
            EV_INFO << " (encrypted)";
        }
        EV_INFO << ", Result: " << result << "\n";
        
        delete msg;
    }
    
    void handleRetransmit() {
        // Retransmit unacknowledged packets
        for (auto& conn : tcpConnections) {
            if (conn.second.state == TCP_SYN_SENT) {
                EV_WARN << "PC" << addr << " retransmitting SYN to " << conn.first << "\n";
                // Retransmit logic here
            }
        }
    }
    
    void handleCongestionTimeout() {
        // Handle congestion timeout (reduce cwnd)
        ssthresh = cwnd / 2;
        cwnd = 1.0;
        dupAckCount = 0;
        EV_INFO << "PC" << addr << " congestion timeout, cwnd reset\n";
    }

    void finish() override {
        cancelAndDelete(startEvt);
        cancelAndDelete(retransmitTimer);
        cancelAndDelete(congestionTimer);
        
        // Clean up transmission queue
        if (endTxEvent != nullptr) {
            cancelAndDelete(endTxEvent);
        }
        while (!txQueue.isEmpty()) {
            delete txQueue.pop();
        }
        
        while (!sendQueue.empty()) {
            delete sendQueue.top();
            sendQueue.pop();
        }
    }
};
Define_Module(PC);

