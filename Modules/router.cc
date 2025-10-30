#include <omnetpp.h>
#include "helpers.h"
#include <map>
#include <vector>
#include <sstream>
using namespace omnetpp;
using namespace std;

class Router : public cSimpleModule {
  private:
    map<long, RouteEntry> routingTable;    // Destination -> RouteEntry
    map<long, LinkState> linkStateDB;      // OSPF link state database
    map<long, map<long, double>> ripTable; // RIP: dest -> (nextHop -> metric)
    
    long routerId;
    string routingProtocol;  // "OSPF-TE" or "RIP" or "STATIC"
    
    // OSPF parameters
    double ospfHelloInterval;
    double ospfLSAInterval;
    cMessage* ospfHelloTimer;
    cMessage* ospfLSATimer;
    
    // RIP parameters
    double ripUpdateInterval;
    cMessage* ripUpdateTimer;
    
    // Traffic Engineering
    map<int, double> linkBandwidth;      // gate -> available bandwidth
    map<int, double> linkUtilization;    // gate -> current utilization
    
    // SYN flood protection
    map<long, int> synCounts;            // src address -> count
    double synRateLimit;
    cMessage* rateLimitResetTimer;
    
    // Priority queue for congestion management
    vector<priority_queue<cMessage*, vector<cMessage*>, MessagePriorityCompare>> outputQueues;
    
    // Transmission queue management
    map<int, cQueue> txQueue;  // per-gate transmission queues
    map<int, cMessage*> endTxEvent;  // per-gate end of transmission events
    
  protected:
    void initialize() override {
        routerId = par("address");
        routingProtocol = par("routingProtocol").stdstringValue();
        
        // Initialize static routes if provided
        const char* s = par("routes").stringValue();
        stringstream ss(s ? s : "");
        string item;
        while (getline(ss, item, ',')) {
            if (item.empty()) continue;
            long d=-1; int g=-1;
            if (sscanf(item.c_str(), "%ld:%d", &d, &g) == 2) {
                RouteEntry re;
                re.destAddr = d;
                re.nextHop = g;
                re.metric = 1.0;
                re.hopCount = 1;
                re.bandwidth = 100.0;
                re.delay = 1.0;
                routingTable[d] = re;
            }
        }
        
        // Initialize link bandwidth tracking and tx queues
        for (int i = 0; i < gateSize("pppg"); i++) {
            linkBandwidth[i] = 100.0;  // 100 Mbps default
            linkUtilization[i] = 0.0;
            outputQueues.push_back(priority_queue<cMessage*, vector<cMessage*>, MessagePriorityCompare>());
            txQueue[i].setName(("txQueue-" + to_string(i)).c_str());
            endTxEvent[i] = nullptr;
        }
        
        // SYN flood protection
        synRateLimit = par("synRateLimit").doubleValue();
        rateLimitResetTimer = new cMessage("rateLimitReset");
        scheduleAt(simTime() + 1.0, rateLimitResetTimer);
        
        // Setup routing protocol timers
        if (routingProtocol == "OSPF-TE") {
            ospfHelloInterval = par("ospfHelloInterval").doubleValue();
            ospfLSAInterval = par("ospfLSAInterval").doubleValue();
            
            ospfHelloTimer = new cMessage("ospfHello");
            ospfLSATimer = new cMessage("ospfLSA");
            
            scheduleAt(simTime() + uniform(0, 1), ospfHelloTimer);
            scheduleAt(simTime() + uniform(0, 2), ospfLSATimer);
            
            EV_INFO << "Router " << routerId << " initialized with OSPF-TE\n";
        } else if (routingProtocol == "RIP") {
            ripUpdateInterval = par("ripUpdateInterval").doubleValue();
            ripUpdateTimer = new cMessage("ripUpdate");
            scheduleAt(simTime() + uniform(0, ripUpdateInterval), ripUpdateTimer);
            
            EV_INFO << "Router " << routerId << " initialized with RIP\n";
        }
    }

    void handleMessage(cMessage *msg) override {
        if (msg->isSelfMessage()) {
            handleSelfMessage(msg);
            return;
        }
        
        int kind = msg->getKind();
        
        // Handle routing protocol messages
        if (kind == OSPF_HELLO) {
            handleOSPFHello(msg);
            return;
        } else if (kind == OSPF_LSA || kind == OSPF_TE_UPDATE) {
            handleOSPFLSA(msg);
            return;
        } else if (kind == RIP_UPDATE) {
            handleRIPUpdate(msg);
            return;
        } else if (kind == RIP_REQUEST) {
            handleRIPRequest(msg);
            return;
        }
        
        // SYN flood protection
        if (kind == TCP_SYN) {
            long src = SRC(msg);
            synCounts[src]++;
            if (synCounts[src] > synRateLimit) {
                EV_WARN << "Router " << routerId << " dropping SYN from " << src 
                        << " - rate limit exceeded\n";
                delete msg;
                return;
            }
        }
        
        // Forward data packets
        forwardPacket(msg);
    }
    
    void handleSelfMessage(cMessage* msg) {
        if (msg == ospfHelloTimer) {
            sendOSPFHello();
            scheduleAt(simTime() + ospfHelloInterval, ospfHelloTimer);
        } else if (msg == ospfLSATimer) {
            sendOSPFLSA();
            scheduleAt(simTime() + ospfLSAInterval, ospfLSATimer);
        } else if (msg == ripUpdateTimer) {
            sendRIPUpdate();
            scheduleAt(simTime() + ripUpdateInterval, ripUpdateTimer);
        } else if (msg == rateLimitResetTimer) {
            synCounts.clear();  // Reset SYN counters
            scheduleAt(simTime() + 1.0, rateLimitResetTimer);
        } else {
            // Handle end of transmission events
            for (int i = 0; i < gateSize("pppg"); i++) {
                if (msg == endTxEvent[i]) {
                    endTxEvent[i] = nullptr;
                    // Send next packet in queue if available
                    if (!txQueue[i].isEmpty()) {
                        cMessage* nextMsg = (cMessage*)txQueue[i].pop();
                        startTransmission(nextMsg, i);
                    }
                    return;
                }
            }
            delete msg;
        }
    }
    
    void startTransmission(cMessage* msg, int gateIndex) {
        cGate* outGate = gate("pppg$o", gateIndex);
        
        // Send the packet
        send(msg, outGate);
        
        // Schedule end of transmission event
        simtime_t finishTime = outGate->getTransmissionChannel()->getTransmissionFinishTime();
        if (finishTime > simTime()) {
            if (endTxEvent[gateIndex] == nullptr) {
                endTxEvent[gateIndex] = new cMessage("endTx");
            } else if (endTxEvent[gateIndex]->isScheduled()) {
                cancelEvent(endTxEvent[gateIndex]);
            }
            scheduleAt(finishTime, endTxEvent[gateIndex]);
        }
    }
    
    void sendPacketOnGate(cMessage* msg, int gateIndex) {
        cGate* outGate = gate("pppg$o", gateIndex);
        
        // Check if channel is busy
        if (outGate->getTransmissionChannel()) {
            simtime_t finishTime = outGate->getTransmissionChannel()->getTransmissionFinishTime();
            if (finishTime > simTime()) {
                // Channel is busy, queue the packet
                txQueue[gateIndex].insert(msg);
                EV_INFO << "Router " << routerId << " queued packet on gate " << gateIndex << "\n";
                return;
            }
        }
        
        // Channel is idle, send immediately
        startTransmission(msg, gateIndex);
    }
    
    void sendOSPFHello() {
        // Send OSPF Hello to all neighbors
        for (int i = 0; i < gateSize("pppg"); i++) {
            auto* hello = mk("OSPF_HELLO", OSPF_HELLO, routerId, -1);
            hello->par("priority").setLongValue(PRIORITY_HIGH);
            sendPacketOnGate(hello, i);
        }
        EV_INFO << "Router " << routerId << " sent OSPF Hello\n";
    }
    
    void sendOSPFLSA() {
        // Send Link State Advertisement with Traffic Engineering info
        for (int i = 0; i < gateSize("pppg"); i++) {
            LinkState ls;
            ls.routerId = routerId;
            ls.linkId = i;
            ls.cost = 1.0 / (linkBandwidth[i] - linkUtilization[i] + 1); // Cost based on available BW
            ls.bandwidth = linkBandwidth[i] - linkUtilization[i];
            ls.delay = 1.0;  // Could be measured
            ls.timestamp = simTime();
            
            auto* lsa = mk("OSPF_LSA", OSPF_TE_UPDATE, routerId, -1);
            lsa->addPar("linkId").setLongValue(i);
            lsa->addPar("cost").setDoubleValue(ls.cost);
            lsa->addPar("bandwidth").setDoubleValue(ls.bandwidth);
            lsa->addPar("delay").setDoubleValue(ls.delay);
            lsa->par("priority").setLongValue(PRIORITY_HIGH);
            
            // Flood to all neighbors
            for (int j = 0; j < gateSize("pppg"); j++) {
                if (j != i) {
                    sendPacketOnGate(lsa->dup(), j);
                }
            }
            delete lsa;
        }
        EV_INFO << "Router " << routerId << " sent OSPF-TE LSA\n";
    }
    
    void handleOSPFHello(cMessage* msg) {
        long neighborId = SRC(msg);
        EV_INFO << "Router " << routerId << " received OSPF Hello from " << neighborId << "\n";
        delete msg;
    }
    
    void handleOSPFLSA(cMessage* msg) {
        long originRouter = SRC(msg);
        int linkId = msg->par("linkId").longValue();
        double cost = msg->par("cost").doubleValue();
        double bandwidth = msg->par("bandwidth").doubleValue();
        double delay = msg->par("delay").doubleValue();
        
        // Update link state database
        LinkState ls;
        ls.routerId = originRouter;
        ls.linkId = linkId;
        ls.cost = cost;
        ls.bandwidth = bandwidth;
        ls.delay = delay;
        ls.timestamp = simTime();
        
        linkStateDB[originRouter * 1000 + linkId] = ls;
        
        // Recompute routes using Dijkstra with TE constraints
        computeOSPFRoutes();
        
        // Flood LSA to other neighbors (except where it came from)
        int inGate = msg->getArrivalGate()->getIndex();
        for (int i = 0; i < gateSize("pppg"); i++) {
            if (i != inGate) {
                sendPacketOnGate(msg->dup(), i);
            }
        }
        delete msg;
        
        EV_INFO << "Router " << routerId << " processed OSPF-TE LSA from " << originRouter << "\n";
    }
    
    void computeOSPFRoutes() {
        // Simplified Dijkstra with Traffic Engineering
        // In a full implementation, this would use the link state database
        // to compute shortest paths considering bandwidth and delay constraints
        EV_INFO << "Router " << routerId << " recomputing OSPF routes\n";
    }
    
    void sendRIPUpdate() {
        // Send RIP distance vector updates
        for (int i = 0; i < gateSize("pppg"); i++) {
            auto* update = mk("RIP_UPDATE", RIP_UPDATE, routerId, -1);
            
            // Add routing table entries to message
            stringstream ss;
            for (auto& entry : routingTable) {
                ss << entry.first << ":" << entry.second.metric << ":" 
                   << entry.second.hopCount << ",";
            }
            update->addPar("routes").setStringValue(ss.str().c_str());
            update->par("priority").setLongValue(PRIORITY_NORMAL);
            
            sendPacketOnGate(update, i);
        }
        EV_INFO << "Router " << routerId << " sent RIP update\n";
    }
    
    void handleRIPUpdate(cMessage* msg) {
        long neighborId = SRC(msg);
        int inGate = msg->getArrivalGate()->getIndex();
        string routes = msg->par("routes").stringValue();
        
        // Parse received routes
        stringstream ss(routes);
        string item;
        bool routeChanged = false;
        
        while (getline(ss, item, ',')) {
            if (item.empty()) continue;
            long dest; double metric; int hops;
            if (sscanf(item.c_str(), "%ld:%lf:%d", &dest, &metric, &hops) == 3) {
                double newMetric = metric + 1.0;  // Add one hop
                int newHops = hops + 1;
                
                if (newHops < 16) {  // RIP hop limit
                    auto it = routingTable.find(dest);
                    if (it == routingTable.end() || newMetric < it->second.metric) {
                        RouteEntry re;
                        re.destAddr = dest;
                        re.nextHop = inGate;
                        re.metric = newMetric;
                        re.hopCount = newHops;
                        re.lastUpdate = simTime();
                        routingTable[dest] = re;
                        routeChanged = true;
                    }
                }
            }
        }
        
        if (routeChanged) {
            EV_INFO << "Router " << routerId << " updated routes from RIP neighbor " 
                    << neighborId << "\n";
        }
        
        delete msg;
    }
    
    void handleRIPRequest(cMessage* msg) {
        // Respond to RIP request with full routing table
        sendRIPUpdate();
        delete msg;
    }
    
    void forwardPacket(cMessage* msg) {
        long dst = DST(msg);
        auto it = routingTable.find(dst);
        
        if (it != routingTable.end()) {
            int g = it->second.nextHop;
            if (g >= 0 && g < gateSize("pppg")) {
                // Update link utilization (simplified)
                cPacket* pkt = dynamic_cast<cPacket*>(msg);
                double msgSize = pkt && pkt->getByteLength() > 0 ? pkt->getByteLength() : 1000;
                linkUtilization[g] += msgSize / 1000000.0;  // Convert to Mbps
                
                // Priority-based forwarding
                int priority = PRIORITY(msg);
                if (priority >= PRIORITY_HIGH || outputQueues[g].empty()) {
                    sendPacketOnGate(msg, g);
                    EV_INFO << "Router " << routerId << " forwarded to gate " << g 
                            << " (priority " << priority << ")\n";
                } else {
                    outputQueues[g].push(msg);
                    EV_INFO << "Router " << routerId << " queued message for gate " << g << "\n";
                }
                return;
            }
        }
        
        // Fallback: flood (skip incoming gate)
        EV_WARN << "Router " << routerId << " no route to " << dst << ", flooding\n";
        int inIdx = msg->getArrivalGate()->getIndex();
        for (int i=0; i<gateSize("pppg"); ++i) {
            if (i != inIdx) {
                sendPacketOnGate(msg->dup(), i);
            }
        }
        delete msg;
    }

    void finish() override {
        cancelAndDelete(ospfHelloTimer);
        cancelAndDelete(ospfLSATimer);
        cancelAndDelete(ripUpdateTimer);
        cancelAndDelete(rateLimitResetTimer);
        
        // Clean up transmission queues and events
        for (int i = 0; i < gateSize("pppg"); i++) {
            while (!txQueue[i].isEmpty()) {
                cMessage* msg = (cMessage*)txQueue[i].pop();
                delete msg;
            }
            if (endTxEvent[i]) {
                cancelAndDelete(endTxEvent[i]);
                endTxEvent[i] = nullptr;
            }
        }
        
        // Clear queues
        for (auto& queue : outputQueues) {
            while (!queue.empty()) {
                delete queue.top();
                queue.pop();
            }
        }
    }
};
Define_Module(Router);

