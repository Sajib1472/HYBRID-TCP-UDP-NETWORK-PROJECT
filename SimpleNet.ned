package hybrid_tcp_udp;

// Channel definitions for different link types
channel FastEthernet extends ned.DatarateChannel
{
    datarate = 100Mbps;
    delay = 0.5ms;
}

channel GigabitEthernet extends ned.DatarateChannel
{
    datarate = 1Gbps;
    delay = 0.1ms;
}

// Router with dynamic routing capabilities
simple Router
{
    parameters:
        int address;
        string routes = default("");   // Static routes fallback
        string routingProtocol = default("OSPF-TE");  // "OSPF-TE", "RIP", or "STATIC"
        double ospfHelloInterval @unit(s) = default(10s);
        double ospfLSAInterval @unit(s) = default(30s);
        double ripUpdateInterval @unit(s) = default(30s);
        double synRateLimit = default(100);  // SYN packets per second
        @display("i=device/router");
    gates:
        inout pppg[];  // Variable-size gate for flexible topology
}

// PC/Client with hybrid TCP-UDP support
simple PC
{
    parameters:
        int address;
        int dnsAddr = default(2);
        string dnsQuery = default("example.com");
        double startAt @unit(s) = default(0.5s);
        string protocol = default("AUTO");  // "TCP", "UDP", or "AUTO"
        @display("i=device/laptop");
    gates:
        inout ppp;
}

// DNS Server with security and rate limiting
simple DNS
{
    parameters:
        int address;
        int answerAddr = default(3);
        double rateLimit = default(1000);  // Requests per second
        @display("i=device/server");
    gates:
        inout ppp;
}

// HTTP Server with hybrid protocol support
simple HTTP
{
    parameters:
        int address;
        double serviceTime @unit(s) = default(5ms);
        int pageSizeBytes = default(20000);
        double synRateLimit = default(100);  // SYN flood protection
        @display("i=device/server");
    gates:
        inout ppp;
}

// Mail Server for email services
simple MailServer
{
    parameters:
        int address;
        double serviceTime @unit(s) = default(10ms);
        int mailSizeBytes = default(50000);
        double synRateLimit = default(100);
        @display("i=device/server");
    gates:
        inout ppp;
}

// Database Server
simple DatabaseServer
{
    parameters:
        int address;
        double queryTime @unit(s) = default(5ms);
        int responseBytes = default(10000);
        double synRateLimit = default(150);
        @display("i=device/server");
    gates:
        inout ppp;
}

// Simplified network with 1 Autonomous System and 3 Subnets
network SimpleNet
{
    submodules:
        // ==================== CORE ROUTER (Central Hub) ====================
        coreRouter: Router {
            parameters:
                address = 100;
                routes = "200:0,300:1,400:2";  // Routes to 3 subnets
                routingProtocol = "OSPF-TE";
                @display("p=400,300");
        }
        
        
        // ==================== SUBNET 1: CLIENT NETWORK ====================
        subnet1Router: Router {
            parameters:
                address = 200;
                routes = "100:3,301:4";  // Core router and DNS
                routingProtocol = "OSPF-TE";
                @display("p=200,150");
        }
        
        // Client PCs (3 PCs)
        clientPC1: PC {
            parameters:
                address = 201;
                dnsAddr = 301;
                protocol = "TCP";
                startAt = 0.5s;
                @display("p=100,100");
        }
        clientPC2: PC {
            parameters:
                address = 202;
                dnsAddr = 301;
                protocol = "UDP";
                startAt = 1.0s;
                @display("p=100,150");
        }
        clientPC3: PC {
            parameters:
                address = 203;
                dnsAddr = 301;
                protocol = "AUTO";
                startAt = 1.5s;
                @display("p=100,200");
        }
        
        // Client DNS
        clientDNS: DNS {
            parameters:
                address = 301;
                answerAddr = 401;  // Points to webServer
                rateLimit = 2000;
                @display("p=200,50");
        }
        
        
        // ==================== SUBNET 2: SERVER NETWORK ====================
        subnet2Router: Router {
            parameters:
                address = 300;
                routes = "100:2,401:3,402:4";  // Core router and servers
                routingProtocol = "OSPF-TE";
                @display("p=600,150");
        }
        
        // Web Servers (2 servers)
        webServer1: HTTP {
            parameters:
                address = 401;
                serviceTime = 3ms;
                pageSizeBytes = 20000;
                @display("p=700,100");
        }
        webServer2: HTTP {
            parameters:
                address = 402;
                serviceTime = 3ms;
                pageSizeBytes = 20000;
                @display("p=700,200");
        }
        
        
        // ==================== SUBNET 3: SERVICES NETWORK ====================
        subnet3Router: Router {
            parameters:
                address = 400;
                routes = "100:0,501:1,601:2";  // Core router, mail server, and database
                routingProtocol = "OSPF-TE";
                @display("p=400,500");
        }
        
        // Mail Server
        mailServer: MailServer {
            parameters:
                address = 501;
                serviceTime = 8ms;
                mailSizeBytes = 50000;
                @display("p=450,550");
        }
        
        // Database Server
        dbServer: DatabaseServer {
            parameters:
                address = 601;
                queryTime = 5ms;
                responseBytes = 10000;
                @display("p=550,550");
        }
        
    connections:
        // ==================== SUBNET 1 CONNECTIONS ====================
        // Client PCs to Subnet1 Router
        clientPC1.ppp <--> FastEthernet <--> subnet1Router.pppg++;
        clientPC2.ppp <--> FastEthernet <--> subnet1Router.pppg++;
        clientPC3.ppp <--> FastEthernet <--> subnet1Router.pppg++;
        
        // DNS to Subnet1 Router
        clientDNS.ppp <--> GigabitEthernet <--> subnet1Router.pppg++;
        
        // Subnet1 Router to Core Router
        subnet1Router.pppg++ <--> GigabitEthernet <--> coreRouter.pppg++;
        
        
        // ==================== SUBNET 2 CONNECTIONS ====================
        // Core Router to Subnet2 Router
        coreRouter.pppg++ <--> GigabitEthernet <--> subnet2Router.pppg++;
        
        // Servers to Subnet2 Router
        webServer1.ppp <--> GigabitEthernet <--> subnet2Router.pppg++;
        webServer2.ppp <--> GigabitEthernet <--> subnet2Router.pppg++;
        
        
        // ==================== SUBNET 3 CONNECTIONS ====================
        // Core Router to Subnet3 Router
        coreRouter.pppg++ <--> GigabitEthernet <--> subnet3Router.pppg++;
        
        // Mail Server to Subnet3 Router
        mailServer.ppp <--> GigabitEthernet <--> subnet3Router.pppg++;
        
        // Database Server to Subnet3 Router
        dbServer.ppp <--> GigabitEthernet <--> subnet3Router.pppg++;
}



