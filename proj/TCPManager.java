/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Description: Fishnet TCP manager</p>
 *
 * <p>Copyright: Copyright (c) 2006</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Hao Wang
 * @version 1.0
 */
public class TCPManager {
    public static final int MAX_SOCKETS = 10;
    private Node node;
    private int addr; // local Address
    private Manager manager;
    private TCPSock[] sockets;
    private int createdSockets;

    public SecureSocket secureSock;

    private static final byte dummy[] = new byte[0];

    public TCPManager(Node node, int addr, Manager manager) {
        this.node = node;
        this.addr = addr;
        this.manager = manager;
        this.sockets = new TCPSock[MAX_SOCKETS];
        for (int i = 0; i < MAX_SOCKETS; i++) {
            sockets[i] = null;
        }
        this.createdSockets = 0;
    }

    public void removeSocket(TCPSock socket) {
        for (int i = 0; i < MAX_SOCKETS; i++) {
            if (this.sockets[i] != null && this.sockets[i].getId() == socket.getId()) {
                this.sockets[i] = null;
            }
        }
    }

    public void addSocket(TCPSock socket) {
        for (int i = 0; i < MAX_SOCKETS; i++) {
            if (this.sockets[i] == null) {
                this.sockets[i] = socket;
                break;
            }
        }
        createdSockets++;
    }

    /**
     * Start this TCP manager
     */
    public void start() {
    }

    /*
     * Begin socket API
     */

    /**
     * Create a socket
     *
     * @return TCPSock the newly created socket, which is not yet bound to
     *                 a local port
     */
    public TCPSock socket() {
        TCPSock new_socket = new TCPSock(this, this.addr, this.createdSockets);
        // save new socket in array
        addSocket(new_socket);
        return new_socket;
    }

    public boolean portNotInUse(int localPort) {
        for (int i = 0; i < this.createdSockets; i++) {
            if (this.sockets[i].getSrcPort() == localPort) {
                return false;
            }
        }
        return true;
    }

    public void manOnReceive(int srcAddr, Packet packet) {
        // extract the Transport data-structure from payload bytestring in packet
        Transport trsp = Transport.unpack(packet.getPayload());
        // flip src and dst to account for the fact that this is an incoming connection
        int srcPort = trsp.getDestPort();
        int dstPort = trsp.getSrcPort();
        int dstAddr = srcAddr;
        srcAddr = packet.getDest();
        // flipping src and dst
        TCPSock curr_sock = getSocket(srcAddr, srcPort, dstAddr, dstPort, trsp.getType() == Transport.SYN);
        curr_sock.onReceive(dstAddr, srcAddr, trsp);
    }

    public TCPSock getSocket(int srcAddr, int srcPort, int dstAddr, int dstPort, boolean listenSocket) {
        for (int i = 0; i < createdSockets; i++) {
            if (this.sockets[i].getSrcPort() == srcPort && this.sockets[i].getSrcAddr() == srcAddr && this.sockets[i].getDstPort() == dstPort && this.sockets[i].getDstAddr() == dstAddr) {
                return this.sockets[i];
            } else if (listenSocket && this.sockets[i].getSrcAddr() == srcAddr && this.sockets[i].getSrcPort() == srcPort) {
                return this.sockets[i];
            }
        }
        return null;
    }

    public void send(int srcAddr, int dstAddr, int srcPort, int dstPort, int transportType, byte[] payload, int seqNum, int remainingWindow) {
        //System.out.println("creating segment with seqNum " + seqNum);
        Transport segment = new Transport(srcPort, dstPort, transportType, remainingWindow, seqNum, payload);
        node.sendSegment(srcAddr, dstAddr, Protocol.TRANSPORT_PKT, segment.pack());
    }

    public void send_message(TCPSock sock, int transportType, byte[] payload) {
        // TODO fix this
        if (transportType == Transport.SERVER_HELLO) {
            sock.setDstAddr(1);
            sock.setDstPort(40);
        }
        Transport segment = new Transport(sock.getSrcPort(), sock.getDstPort(), transportType, 0, 0, payload);
        node.sendSegment(sock.getSrcAddr(), sock.getDstAddr(), Protocol.TRANSPORT_PKT, segment.pack());
    }


    public void startTimer(int amount, Callback callback) {
        this.manager.addTimerAt(this.addr, amount + this.manager.now(), callback);
    }

    public int updateCreatedSocketsCount() {
        this.createdSockets++;
        return this.createdSockets - 1;
    }
    /*
     * End Socket API
     */
}
// establishedSockets in Listen port
// TCP manager also keeps track of port number that are reserved