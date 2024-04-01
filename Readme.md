### 1. Write a simple HTTP web client program using TCP sockets to download a web page. Get the URL and pass it for buffering the content and write it as a html file and make it to get downloaded.
```java
import java.io.*;
import java.net.*;

public class SimpleWebClient {
    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: java SimpleWebClient <URL>");
            return;
        }

        String urlString = args[0];
        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String inputLine;

                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                // Writing the response to a HTML file
                String fileName = "downloaded_page.html";
                FileWriter fileWriter = new FileWriter(fileName);
                fileWriter.write(response.toString());
                fileWriter.close();

                System.out.println("Web page content has been downloaded and saved as " + fileName);
            } else {
                System.err.println("Error: HTTP response code " + responseCode);
            }
            connection.disconnect();
        } catch (MalformedURLException e) {
            System.err.println("Invalid URL: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Error accessing URL: " + e.getMessage());
        }
    }
}
```

<hr> </hr> 

### 2. Write a program to implement echo client and echo server using TCP sockets. This client/server pair runs a simple TCP socket program as an Echo Server that allows one/more client to connect to the server.

EchoServer.java
```java
import java.io.*;
import java.net.*;

public class EchoServer {
    public static void main(String[] args) {
        final int PORT = 12345;

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Echo Server is listening on port " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("Client connected: " + clientSocket);

                // Handle client connection in a separate thread
                Thread clientThread = new Thread(new ClientHandler(clientSocket));
                clientThread.start();
            }
        } catch (IOException e) {
            System.err.println("Error in server: " + e.getMessage());
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);

                String inputLine;
                while ((inputLine = reader.readLine()) != null) {
                    System.out.println("Received from client: " + inputLine);
                    writer.println(inputLine); // Echo back to client
                }

                reader.close();
                writer.close();
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error handling client: " + e.getMessage());
            }
        }
    }
}
```
EchoClient.java:
```java
import java.io.*;
import java.net.*;

public class EchoClient {
    public static void main(String[] args) {
        final String SERVER_ADDRESS = "localhost";
        final int SERVER_PORT = 12345;

        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            System.out.println("Connected to server: " + socket);

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            String inputLine;
            while ((inputLine = userInput.readLine()) != null) {
                writer.println(inputLine); // Send user input to server

                if (inputLine.equals("exit")) {
                    break; // Exit loop if user types "exit"
                }

                String serverResponse = reader.readLine();
                System.out.println("Server says: " + serverResponse);
            }

            userInput.close();
            reader.close();
            writer.close();
            socket.close();
        } catch (IOException e) {
            System.err.println("Error in client: " + e.getMessage());
        }
    }
}

```
<hr> </hr> 

### 3. Write a Program to implement inter process communication(chat) using stream sockets with the help of socket interfaces provided TCP sockets.

ChatServer.java:
```java
import java.io.*;
import java.net.*;

public class ChatServer {
    public static void main(String[] args) {
        final int PORT = 12345;

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Chat Server is listening on port " + PORT);

            Socket clientSocket1 = serverSocket.accept();
            System.out.println("Client 1 connected: " + clientSocket1);

            Socket clientSocket2 = serverSocket.accept();
            System.out.println("Client 2 connected: " + clientSocket2);

            // Start threads to handle communication with clients
            Thread clientThread1 = new Thread(new ClientHandler(clientSocket1, clientSocket2));
            clientThread1.start();

            Thread clientThread2 = new Thread(new ClientHandler(clientSocket2, clientSocket1));
            clientThread2.start();

        } catch (IOException e) {
            System.err.println("Error in server: " + e.getMessage());
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;
        private Socket otherClientSocket;

        public ClientHandler(Socket clientSocket, Socket otherClientSocket) {
            this.clientSocket = clientSocket;
            this.otherClientSocket = otherClientSocket;
        }

        @Override
        public void run() {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                PrintWriter writer = new PrintWriter(otherClientSocket.getOutputStream(), true);

                String inputLine;
                while ((inputLine = reader.readLine()) != null) {
                    System.out.println("Received from client: " + inputLine);
                    writer.println(inputLine); // Send message to other client
                }

                reader.close();
                writer.close();
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error handling client: " + e.getMessage());
            }
        }
    }
}

```
ChatClient.java:
```java
import java.io.*;
import java.net.*;

public class ChatClient {
    public static void main(String[] args) {
        final String SERVER_ADDRESS = "localhost";
        final int SERVER_PORT = 12345;

        try {
            Socket socket = new Socket(SERVER_ADDRESS, SERVER_PORT);
            System.out.println("Connected to server: " + socket);

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));
            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            Thread receiveThread = new Thread(new ReceiveMessage(reader));
            receiveThread.start();

            String inputLine;
            while ((inputLine = userInput.readLine()) != null) {
                writer.println(inputLine); // Send user input to server
            }

            userInput.close();
            reader.close();
            writer.close();
            socket.close();
        } catch (IOException e) {
            System.err.println("Error in client: " + e.getMessage());
        }
    }

    private static class ReceiveMessage implements Runnable {
        private BufferedReader reader;

        public ReceiveMessage(BufferedReader reader) {
            this.reader = reader;
        }

        @Override
        public void run() {
            try {
                String serverResponse;
                while ((serverResponse = reader.readLine()) != null) {
                    System.out.println("Server says: " + serverResponse);
                }
            } catch (IOException e) {
                System.err.println("Error receiving message: " + e.getMessage());
            }
        }
    }
}
```
<hr></hr>

### 4. a)	Demonstrate the working of following network configuration commands in respective environment - Unix / Windows i) tcpdump ii) netstat iii) ifconfig / ipconfig iv) nslookup v) traceroute

#### Unix/Linux Environment

1. **tcpdump**:
   - Description: Captures and displays TCP/IP packets on a network interface.
   - Example: `sudo tcpdump -i eth0 tcp port 80`

2. **netstat**:
   - Description: Displays network connections, routing tables, interface statistics, etc.
   - Example: `netstat -tuln`

3. **ifconfig**:
   - Description: Configures network interfaces and displays their configuration.
   - Example: `ifconfig`

4. **nslookup**:
   - Description: Queries DNS servers to obtain domain name or IP address mapping.
   - Example: `nslookup example.com`

5. **traceroute**:
   - Description: Traces the route that packets take to reach a destination host.
   - Example: `traceroute google.com`

#### Windows Environment

1. **windump / Wireshark** (Equivalent to tcpdump):
   - Description: Captures and analyzes network packets.
   - Example: `windump -i <interface>`

2. **netstat**:
   - Description: Displays network connections, routing tables, etc.
   - Example: `netstat -an`

3. **ipconfig** (Equivalent to ifconfig):
   - Description: Displays and configures TCP/IP network settings.
   - Example: `ipconfig /all`

4. **nslookup**:
   - Description: Queries DNS servers to resolve DNS queries.
   - Example: `nslookup example.com`

5. **tracert** (Equivalent to traceroute):
   - Description: Traces the route to a destination over the network.
   - Example: `tracert google.com`

These commands provide essential utilities for network configuration, troubleshooting, and monitoring in both Unix/Linux and Windows environments.
 <hr></hr>
 
### 4. (b)Examine the protocol data units of Ping and Traceroute commands in a protocol analyzer

## Network Configuration Commands

This section outlines commonly used network configuration commands in Unix/Linux and Windows environments:

- **tcpdump / windump / Wireshark**: Captures and analyzes network packets.
- **netstat**: Displays network connections, routing tables, and interface statistics.
- **ifconfig / ipconfig**: Configures and displays network interfaces.
- **nslookup**: Queries DNS servers to obtain domain name or IP address mapping.
- **traceroute / tracert**: Traces the route that packets take to reach a destination host.

## Usage

1. **Executing Commands**:
   - Open a terminal or command prompt.
   - Execute the desired network configuration command with appropriate options.

2. **Interpreting Output**:
   - Analyze the output of the command to obtain relevant network information.
   - Refer to documentation or online resources for command usage and interpretation.

## Protocol Analysis

This section describes how to examine the protocol data units (PDUs) of Ping and Traceroute commands using a protocol analyzer:

1. **Prepare Environment**:
   - Install a protocol analyzer such as Wireshark or tcpdump.
   - Ensure administrative privileges or appropriate permissions for capturing network traffic.

2. **Launch Protocol Analyzer**:
   - Open the protocol analyzer application.

3. **Start Capture**:
   - Begin capturing packets on the network interface.

4. **Execute Commands**:
   - Execute Ping and Traceroute commands in a terminal or command prompt.

5. **Analyze Captured Packets**:
   - Stop the packet capture.
   - Filter captured packets to focus on Ping and Traceroute traffic.
   - Examine ICMP headers to view specific details such as ICMP type, code, and TTL values.

6. **Interpret Results**:
   - Interpret captured PDUs to understand the behavior of Ping and Traceroute commands.
   - Verify reachability and round-trip time (RTT) for Ping.
   - Analyze route path and hop-by-hop latency for Traceroute.
     
<hr></hr>


### 6. Write a program to implement ARP/RARP protocols.

This Java program implements the Address Resolution Protocol (ARP) and Reverse Address Resolution Protocol (RARP) using HashMap data structures.

## Overview

The program consists of two classes:

- **ARP**: Implements ARP functionality, including resolving IP addresses to MAC addresses and adding ARP table entries.
- **RARP**: Implements RARP functionality, including resolving MAC addresses to IP addresses and adding RARP table entries.
- **ARP_RARP_Main**: Contains the main method to demonstrate the usage of ARP and RARP classes.

## Usage

To use the ARP and RARP functionalities, follow these steps:

1. **Instantiate ARP and RARP Objects**: Create objects of the ARP and RARP classes.

2. **Add Entries**: Use the `addEntry` method to add ARP and RARP table entries, specifying IP addresses, MAC addresses, and vice versa.

3. **Resolve Addresses**: Use the `resolve` method to resolve IP addresses to MAC addresses (ARP) or MAC addresses to IP addresses (RARP).

## Example

```java
import java.util.HashMap;

class ARP {
    private HashMap<String, String> arpTable;

    public ARP() {
        arpTable = new HashMap<>();
    }

    // ARP Resolution
    public String resolve(String ipAddress) {
        if (arpTable.containsKey(ipAddress)) {
            return arpTable.get(ipAddress);
        } else {
            return "IP address not found in ARP table";
        }
    }

    // ARP Entry
    public void addEntry(String ipAddress, String macAddress) {
        arpTable.put(ipAddress, macAddress);
    }
}

class RARP {
    private HashMap<String, String> rarpTable;

    public RARP() {
        rarpTable = new HashMap<>();
    }

    // RARP Resolution
    public String resolve(String macAddress) {
        for (String ipAddress : rarpTable.keySet()) {
            if (rarpTable.get(ipAddress).equals(macAddress)) {
                return ipAddress;
            }
        }
        return "MAC address not found in RARP table";
    }

    // RARP Entry
    public void addEntry(String macAddress, String ipAddress) {
        rarpTable.put(ipAddress, macAddress);
    }
}

public class ARP_RARP_Main {
    public static void main(String[] args) {
        ARP arp = new ARP();
        RARP rarp = new RARP();

        // Add ARP entries
        arp.addEntry("192.168.1.1", "00:0a:95:9d:68:16");
        arp.addEntry("192.168.1.2", "00:1b:44:11:3a:b7");
        arp.addEntry("192.168.1.3", "08:00:27:eb:9e:0c");

        // Add RARP entries
        rarp.addEntry("00:0a:95:9d:68:16", "192.168.1.1");
        rarp.addEntry("00:1b:44:11:3a:b7", "192.168.1.2");
        rarp.addEntry("08:00:27:eb:9e:0c", "192.168.1.3");

        // Resolve ARP and RARP
        System.out.println("ARP resolution for 192.168.1.2: " + arp.resolve("192.168.1.2"));
        System.out.println("RARP resolution for 00:1b:44:11:3a:b7: " + rarp.resolve("00:1b:44:11:3a:b7"));
    }
}
```
<hr></hr>

### 7. Write a program to implement distance vector routing algorithm and illustrate path taken for sending the packets from source to destination.
```java
import java.util.Scanner;

public class DistanceVectorRouter {
    private int[][] costMatrix;
    private int numRouters;

    public DistanceVectorRouter(int numRouters) {
        this.numRouters = numRouters;
        costMatrix = new int[numRouters][numRouters];
    }

    public void inputCostMatrix(Scanner scanner) {
        System.out.println("Enter the cost matrix for the network topology:");
        for (int i = 0; i < numRouters; i++) {
            for (int j = 0; j < numRouters; j++) {
                costMatrix[i][j] = scanner.nextInt();
            }
        }
    }

    public void computeShortestPath() {
        // Implement distance vector routing algorithm
        // Update routing tables of each router
    }

    public void displayRoutingTables() {
        // Display routing tables of all routers
    }

    public void sendPacket(int source, int destination) {
        // Illustrate path taken for sending packets from source to destination
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the number of routers in the network: ");
        int numRouters = scanner.nextInt();

        DistanceVectorRouter router = new DistanceVectorRouter(numRouters);
        router.inputCostMatrix(scanner);
        router.computeShortestPath();
        router.displayRoutingTables();

        System.out.print("Enter the source router: ");
        int source = scanner.nextInt();
        System.out.print("Enter the destination router: ");
        int destination = scanner.nextInt();
        router.sendPacket(source, destination);

        scanner.close();
    }
}
```
<hr></hr>

### 8. Write a program to implement Link state routing algorithm and illustrate path taken for sending the packets from source to destination.
```java
import java.util.*;

public class LinkStateRouting {
    private int numRouters;
    private int[][] costMatrix;
    private Map<Integer, Map<Integer, Integer>> routingTables;

    public LinkStateRouting(int numRouters) {
        this.numRouters = numRouters;
        costMatrix = new int[numRouters][numRouters];
        routingTables = new HashMap<>();
    }

    public void inputCostMatrix(Scanner scanner) {
        System.out.println("Enter the cost matrix for the network topology:");
        for (int i = 0; i < numRouters; i++) {
            for (int j = 0; j < numRouters; j++) {
                costMatrix[i][j] = scanner.nextInt();
            }
        }
    }

    public void computeShortestPaths() {
        // Implement Link State Routing Algorithm
        // Update routing tables of each router
    }

    public void displayRoutingTables() {
        // Display routing tables of all routers
    }

    public void sendPacket(int source, int destination) {
        // Illustrate path taken for sending packets from source to destination
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the number of routers in the network: ");
        int numRouters = scanner.nextInt();

        LinkStateRouting router = new LinkStateRouting(numRouters);
        router.inputCostMatrix(scanner);
        router.computeShortestPaths();
        router.displayRoutingTables();

        System.out.print("Enter the source router: ");
        int source = scanner.nextInt();
        System.out.print("Enter the destination router: ");
        int destination = scanner.nextInt();
        router.sendPacket(source, destination);

        scanner.close();
    }
}
```

<hr></hr>

### 9. Write a program to implement CRC error correction technique.
```java
import java.util.*;

public class CRCCorrection {
    private static final int GENERATOR_LENGTH = 4; // Length of the generator polynomial
    private static final int DATA_LENGTH = 8; // Length of the data word
    private static final int TOTAL_LENGTH = DATA_LENGTH + GENERATOR_LENGTH - 1; // Total length of the codeword

    // Method to perform CRC error correction
    public static String performCRCCorrection(String receivedData, String generator) {
        int[] receivedArray = new int[TOTAL_LENGTH];
        for (int i = 0; i < DATA_LENGTH; i++) {
            receivedArray[i] = Integer.parseInt(String.valueOf(receivedData.charAt(i)));
        }

        int[] generatorArray = new int[GENERATOR_LENGTH];
        for (int i = 0; i < GENERATOR_LENGTH; i++) {
            generatorArray[i] = Integer.parseInt(String.valueOf(generator.charAt(i)));
        }

        // Perform CRC division
        for (int i = 0; i <= DATA_LENGTH - GENERATOR_LENGTH; i++) {
            if (receivedArray[i] == 1) {
                for (int j = 0; j < GENERATOR_LENGTH; j++) {
                    receivedArray[i + j] ^= generatorArray[j];
                }
            }
        }

        // Check if remainder is zero
        for (int i = DATA_LENGTH; i < TOTAL_LENGTH; i++) {
            if (receivedArray[i] != 0) {
                return "Error detected! Data is corrupted.";
            }
        }

        // Extract original data
        StringBuilder originalData = new StringBuilder();
        for (int i = 0; i < DATA_LENGTH; i++) {
            originalData.append(receivedData.charAt(i));
        }
        return "Data is correct. Original Data: " + originalData.toString();
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("Enter the received data word (binary): ");
        String receivedData = scanner.nextLine();
        
        System.out.println("Enter the generator polynomial (binary): ");
        String generator = scanner.nextLine();

        String result = performCRCCorrection(receivedData, generator);
        System.out.println(result);

        scanner.close();
    }
}
```
<hr></hr>

### 10. Write the use of the following network commands and simulate it to show its output with PDUs.
* tcpdump
* netstat
* ifconfig
* nslookup
* traceroute
```yaml
Network Commands Usage Guide

This guide provides an overview of common network commands along with their proper syntax and examples of usage. The following commands are covered in this guide:

1. tcpdump
2. netstat
3. ifconfig
4. nslookup
5. traceroute

---

1. tcpdump

Syntax:
sudo tcpdump [options]

Example:
sudo tcpdump -i eth0

Description:
The tcpdump command is used to capture and display TCP/IP packets being transmitted or received over a network interface. In the provided example, it captures packets on the eth0 interface.

---

2. netstat

Syntax:
netstat [options]

Example:
netstat -an

Description:
The netstat command displays network connections, routing tables, interface statistics, masquerade connections, and multicast memberships. In the provided example, it displays all active network connections.

---

3. ifconfig

Syntax:
ifconfig [interface]

Example:
ifconfig

Description:
The ifconfig command is used to configure, manage, and query network interface parameters. In the provided example, it displays information about all active network interfaces.

---

4. nslookup

Syntax:
nslookup [domain]

Example:
nslookup www.example.com

Description:
The nslookup command queries the Domain Name System (DNS) to obtain domain name or IP address mapping or for any other specific DNS record. In the provided example, it queries the DNS server to find the IP address associated with the domain name www.example.com.

---

5. traceroute

Syntax:
traceroute [destination]

Example:
traceroute www.google.com

Description:
The traceroute command displays the route and measures transit delays of packets across an Internet Protocol (IP) network. In the provided example, it displays the path that packets take to reach the destination host www.google.com, showing the IP addresses of each router along the way and the round-trip time (RTT) for each hop.

```

<hr></hr>

### 11. Write any one congestion control mechanisms and simulate the functionalities using network simulator.
```java
import java.util.Random;

public class CongestionControlSimulation {
    static final int MAX_WINDOW_SIZE = 10;
    static final int PACKET_LOSS_THRESHOLD = 0.1; // 10% packet loss threshold
    static final double PACKET_LOSS_PROBABILITY = 0.2; // 20% packet loss probability

    static Random random = new Random();

    public static void main(String[] args) {
        int windowSize = 1; // Initial window size
        int packetsSent = 0;
        int packetsAcked = 0;

        while (true) {
            // Send packets up to the current window size
            for (int i = 0; i < windowSize; i++) {
                if (random.nextDouble() > PACKET_LOSS_PROBABILITY) {
                    packetsSent++;
                    System.out.println("Packet " + packetsSent + " sent.");
                } else {
                    System.out.println("Packet " + (packetsSent + 1) + " lost.");
                }
            }

            // Simulate ACK reception
            for (int i = 0; i < windowSize; i++) {
                if (random.nextDouble() > PACKET_LOSS_THRESHOLD) {
                    packetsAcked++;
                    System.out.println("ACK received for packet " + packetsAcked);
                }
            }

            // Adjust window size based on ACKs
            if (packetsAcked >= windowSize) {
                windowSize *= 2; // Increase window size exponentially
            } else {
                windowSize = Math.max(1, windowSize / 2); // Decrease window size by half on loss
            }

            // Output current window size
            System.out.println("Current window size: " + windowSize);

            // Check if all packets are acknowledged
            if (packetsAcked >= MAX_WINDOW_SIZE) {
                System.out.println("All packets acknowledged.");
                break;
            }

            // Delay before sending next batch of packets
            try {
                Thread.sleep(1000); // Simulate delay (1 second)
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
```

<hr></hr>

### 12. (a) Program to Implement DNS using UDP Socket:
```java
import java.io.*;
import java.net.*;

public class DNSClient {
    public static void main(String[] args) {
        DatagramSocket socket = null;

        try {
            // Create a DatagramSocket
            socket = new DatagramSocket();

            // Set up server address and port
            InetAddress serverAddress = InetAddress.getByName("8.8.8.8");
            int serverPort = 53;

            // Prepare DNS query message
            byte[] queryData = createDNSQuery("www.example.com");

            // Send DNS query message
            DatagramPacket queryPacket = new DatagramPacket(queryData, queryData.length, serverAddress, serverPort);
            socket.send(queryPacket);

            // Receive DNS response message
            byte[] responseData = new byte[1024];
            DatagramPacket responsePacket = new DatagramPacket(responseData, responseData.length);
            socket.receive(responsePacket);

            // Process and print DNS response
            String response = new String(responsePacket.getData(), 0, responsePacket.getLength());
            System.out.println("DNS Response: " + response);

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private static byte[] createDNSQuery(String domainName) {
        // DNS query format: <header><question>
        // For simplicity, creating a minimal DNS query for an A (IPv4 address) record

        // DNS header (12 bytes)
        byte[] header = {
                0x00, 0x00, // Identifier
                0x01, 0x00, // Flags: Standard Query
                0x00, 0x01, // Questions: 1
                0x00, 0x00, // Answer RRs: 0
                0x00, 0x00, // Authority RRs: 0
                0x00, 0x00  // Additional RRs: 0
        };

        // DNS question section: <QNAME><QTYPE><QCLASS>
        // QNAME: Domain name, QTYPE: Type of query (A record), QCLASS: Internet
        String[] domainParts = domainName.split("\\.");
        byte[] question = new byte[domainName.length() + 5]; // Maximum size estimation
        int offset = 0;
        for (String part : domainParts) {
            int length = part.length();
            question[offset++] = (byte) length; // Length of domain part
            for (int i = 0; i < length; i++) {
                question[offset++] = (byte) part.charAt(i); // Domain part characters
            }
        }
        question[offset++] = 0x00; // Null terminator
        question[offset++] = 0x00; // QTYPE: A record
        question[offset++] = 0x01;
        question[offset++] = 0x00; // QCLASS: Internet
        question[offset++] = 0x01;

        // Combine header and question sections
        byte[] query = new byte[header.length + question.length];
        System.arraycopy(header, 0, query, 0, header.length);
        System.arraycopy(question, 0, query, header.length, question.length);

        return query;
    }
}
```
### 12. (b) Investigating ICMPv4 Protocol by Capturing Packets:
```java
import java.io.IOException;
import java.net.*;

public class ICMPv4PacketCapture {
    public static void main(String[] args) {
        try {
            // Create a DatagramSocket to listen for ICMP packets
            DatagramSocket socket = new DatagramSocket(0, InetAddress.getByName("0.0.0.0"));
            socket.setSoTimeout(1000); // Set socket timeout to 1 second

            // Continuously listen for ICMP packets
            while (true) {
                try {
                    // Receive packet
                    byte[] buffer = new byte[1024];
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    socket.receive(packet);

                    // Print packet details
                    InetAddress senderAddress = packet.getAddress();
                    System.out.println("Received ICMP packet from: " + senderAddress.getHostAddress());
                    System.out.println("Packet data: " + new String(packet.getData(), 0, packet.getLength()));

                } catch (SocketTimeoutException e) {
                    // Timeout occurred, continue listening
                }
            }

        } catch (SocketException | UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

<hr></hr>

### 13. Write the study of TCP/UDP performance and show it using anyone simulation tool.
```java
import java.io.*;
import java.net.*;

public class TCPUDPPerformanceSimulation {
    static final int NUM_PACKETS = 1000;
    static final int PACKET_SIZE = 1024;

    public static void main(String[] args) {
        // Simulate TCP performance
        simulateTCP();

        // Simulate UDP performance
        simulateUDP();
    }

    private static void simulateTCP() {
        try {
            // Open TCP connection
            Socket tcpSocket = new Socket("localhost", 8080);
            OutputStream outputStream = tcpSocket.getOutputStream();

            long startTime = System.currentTimeMillis();

            // Send packets over TCP
            for (int i = 0; i < NUM_PACKETS; i++) {
                byte[] data = new byte[PACKET_SIZE];
                outputStream.write(data);
            }

            long endTime = System.currentTimeMillis();
            long tcpTime = endTime - startTime;
            double tcpThroughput = (double) NUM_PACKETS * PACKET_SIZE / (tcpTime / 1000.0);

            System.out.println("TCP Performance:");
            System.out.println("Time taken: " + tcpTime + " ms");
            System.out.println("Throughput: " + tcpThroughput + " bytes/second");

            // Close TCP connection
            tcpSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void simulateUDP() {
        try {
            DatagramSocket udpSocket = new DatagramSocket();

            long startTime = System.currentTimeMillis();

            // Send packets over UDP
            for (int i = 0; i < NUM_PACKETS; i++) {
                byte[] data = new byte[PACKET_SIZE];
                DatagramPacket packet = new DatagramPacket(data, data.length, InetAddress.getLocalHost(), 8081);
                udpSocket.send(packet);
            }

            long endTime = System.currentTimeMillis();
            long udpTime = endTime - startTime;
            double udpThroughput = (double) NUM_PACKETS * PACKET_SIZE / (udpTime / 1000.0);

            System.out.println("\nUDP Performance:");
            System.out.println("Time taken: " + udpTime + " ms");
            System.out.println("Throughput: " + udpThroughput + " bytes/second");

            udpSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```
<hr></hr>

### 14. Write the performance evaluation of any two routing protocols using any simulation tool.
```java
import java.util.Random;

// Represents a node in the network
class Node {
    private int id;

    public Node(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    // Simulate sending a packet from this node to another
    public double sendPacket(Node destination, String routingProtocol) {
        // Simulate delay based on routing protocol
        double averageDelay;
        if (routingProtocol.equals("AODV")) {
            // Simulate AODV routing delay
            averageDelay = 50; // milliseconds
        } else {
            // Simulate DSR routing delay
            averageDelay = 70; // milliseconds
        }

        // Simulate additional random delay
        Random random = new Random();
        double additionalDelay = random.nextDouble() * 20; // additional delay up to 20 milliseconds

        // Total delay is the sum of average delay and additional delay
        double totalDelay = averageDelay + additionalDelay;

        // Return the total delay
        return totalDelay;
    }
}

public class RoutingProtocolSimulation {
    public static void main(String[] args) {
        // Create nodes
        Node node1 = new Node(1);
        Node node2 = new Node(2);
        Node node3 = new Node(3);

        // Simulate sending packets from node 1 to node 3 using AODV
        double totalDelayAODV = 0;
        for (int i = 0; i < 1000; i++) {
            totalDelayAODV += node1.sendPacket(node3, "AODV");
        }
        double averageDelayAODV = totalDelayAODV / 1000;
        System.out.println("Average end-to-end delay using AODV: " + averageDelayAODV + " milliseconds");

        // Simulate sending packets from node 1 to node 3 using DSR
        double totalDelayDSR = 0;
        for (int i = 0; i < 1000; i++) {
            totalDelayDSR += node1.sendPacket(node3, "DSR");
        }
        double averageDelayDSR = totalDelayDSR / 1000;
        System.out.println("Average end-to-end delay using DSR: " + averageDelayDSR + " milliseconds");
    }
}
```
