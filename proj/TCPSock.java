/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Description: Fishnet socket implementation</p>
 *
 * <p>Copyright: Copyright (c) 2006</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Hao Wang
 * @version 1.0
 */
import java.util.*;
import java.lang.reflect.Method;

public class TCPSock {
    // TCP socket states
    enum State {
        // protocol states
        CLOSED,
        LISTEN,
        SYN_SENT,
        ESTABLISHED,
        SHUTDOWN, // close requested, FIN not sent (due to unsent data in queue)
        JUST_CREATED
    }

    public static final int SND_BUFF_SIZE = 10000;
    // change to 950 to test flow control!
    public static final int RCV_BUFF_SIZE = 10000;
    public static final int MSS = 8;
    private TCPManager tcpMan;
    private State state;
    private LinkedList<TCPSock> establishedSockets;
    private int srcAddr = -1;
    private int dstAddr = -1;
    private int srcPort = -1;
    private int dstPort = -1;
    private int backlog;
    private int seqNum = -1;
    private byte[] snd_buff;
    private byte[] rcv_buff;
    private int snd_start;
    private int snd_not_ack;
    private int snd_end;
    private int rcv_start;
    private int rcv_end;
    private int rcv_avail;
    private int snd_avail;
    private int sock_id;
    // store how much buffer the connected socket has remaining
    // used for flow control
    private int connected_socket_buffer;
    // congestion window size
    private int cwnd;
    public SecureSocket secureSock;

    public TCPSock(TCPManager tcpMan, int srcAddr, int curr_sock_id) {
        this.tcpMan = tcpMan;
        this.state = State.JUST_CREATED;
        this.srcAddr = srcAddr;
        this.establishedSockets = new LinkedList<TCPSock>();
        this.snd_buff = new byte[SND_BUFF_SIZE];
        this.rcv_buff = new byte[RCV_BUFF_SIZE];
        this.snd_start = this.snd_end = 0;
        this.rcv_start = this.rcv_end = 0;
        this.rcv_avail = RCV_BUFF_SIZE;
        this.snd_avail = SND_BUFF_SIZE;
        this.sock_id = curr_sock_id;
        this.connected_socket_buffer = -1;
       //this.cwnd = 300;
    }

    /*
     * The following are the socket APIs of TCP transport service.
     * All APIs are NON-BLOCKING.
     */
    void onReceive(int dstAddr, int srcAddr, Transport trsp) {
        //System.out.println("receiving packet with seqNum " + trsp.getSeqNum());
        switch(trsp.getType()) {
            case Transport.SYN:
                this.handleSyn(dstAddr, srcAddr, trsp);
                break;
            case Transport.ACK:
                this.handleAck(dstAddr, srcAddr, trsp);
                break;
            case Transport.DATA:
                this.handleData(dstAddr, srcAddr, trsp);
                break;
            case Transport.FIN:
                this.handleFin(dstAddr, srcAddr, trsp);
                break;
            case Transport.CLIENT_HELLO:
            case Transport.SERVER_HELLO:
                this.handleHello(dstAddr, srcAddr, trsp);
                break;
            case Transport.SERVER_AUTHENTICATE:
                this.handleAuthenticate(trsp);
                break;
            case Transport.CLIENT_HANDSHAKE_FINISHED:
            case Transport.SERVER_HANDSHAKE_FINISHED:
                this.handleHandshakeFinished(trsp);
                break;
        }
    }

    private void handleFin(int dstAddr, int srcAddr, Transport trsp) {
        System.out.println("F");
        if (this.state == State.ESTABLISHED) {
            if (this.rcv_start == this.rcv_end) {
                //System.out.println("CLOSING socket due to FIN");
                this.state = State.CLOSED;
            } else {
                //System.out.println("SHUTDOWN socket due to FIN");
                this.state = State.SHUTDOWN;
            }
        }
        // print out data received so far
        System.out.println("************************************************************");
        System.out.println("Received following encrypted content:");
        String receivedData = new String(this.rcv_buff);
        System.out.println(receivedData);
        System.out.println("************************************************************");
    }

    private void handleData(int dstAddr, int srcAddr, Transport trsp) {
        int incomingSeqNum = trsp.getSeqNum();
        //System.out.println(this.srcPort + ": incomingSeqNum: " + incomingSeqNum + " currSeqNum: " + this.rcv_end);
        if (incomingSeqNum == this.rcv_end) {
            System.out.print(".");
            byte[] data = trsp.getPayload();
            // find correct amount of data to write into buffer
            //int len = Math.min(data.length, this.rcv_avail);
            int len = data.length;
            writeToRcvBuff(data, this.rcv_buff, this.rcv_end, 0, len);
            this.rcv_end += len;
            this.rcv_avail -= len;
            // accept data and send back acknowledgement
            //System.out.println("accepted data with seqNum: " + incomingSeqNum);
            this.tcpMan.send(srcAddr, dstAddr, this.srcPort, this.dstPort, Transport.ACK, new byte[0], this.rcv_end, this.rcv_avail);
        }
        // if data not accepted need to resend everything from this.snd_bas to this.snd_not_yet_ack
    }
    //this.tcpMan.send(this.srcAddr, this.dstAddr, this.srcPort, trsp.getSrcPort(), Transport.FIN, new byte[0], trsp.getSeqNum());


    private void writeToRcvBuff(byte[] src, byte[] dst, int dst_start, int src_start, int len) {
        int i;
        for (i = 0; i < len && i < RCV_BUFF_SIZE; i++) {
            //if (this.snd_end + i % BUFF_SIZE >= this.snd_start + i % BUFF_SIZE) break;
            dst[dst_start + i] = src[src_start + i];
        }
    }

    private void handleSyn(int dstAddr, int srcAddr, Transport trsp) {
        System.out.print("S");
        // establish new connection socket
        if (this.state == State.LISTEN) {
            if (this.establishedSockets.size() >= this.backlog) {
                System.out.print("Established more sockets than are allowed by Backlog!");
                this.tcpMan.send(this.srcAddr, this.dstAddr, this.srcPort, trsp.getSrcPort(), Transport.FIN, new byte[0], trsp.getSeqNum(), 0);
                return;
            }
            TCPSock establishedSocket = new TCPSock(this.tcpMan, this.srcAddr, this.tcpMan.updateCreatedSocketsCount());
            establishedSocket.setSrcPort(this.srcPort);
            establishedSocket.setDstPort(trsp.getSrcPort());
            establishedSocket.setDstAddr(dstAddr);
            this.tcpMan.addSocket(establishedSocket);
            this.tcpMan.send(establishedSocket.getSrcAddr(), establishedSocket.getDstAddr(), establishedSocket.getSrcPort(), establishedSocket.getDstPort(), Transport.ACK, new byte[0], trsp.getSeqNum(), 0);
            establishedSocket.setState(State.ESTABLISHED);
            establishedSockets.add(establishedSocket);
            establishedSocket.secureSock = this.tcpMan.secureSock;
        }

    }

    private void handleAck(int dstAddr, int srcAddr, Transport trsp) {
        int incomingSeqNum = trsp.getSeqNum();
        //System.out.println(this.srcPort + ": handleAck::incomingSeqNum: " + incomingSeqNum);
        if (incomingSeqNum == this.rcv_end && this.state == State.SYN_SENT) {
            System.out.print(":");
            this.state = State.ESTABLISHED;
            //this.seqNum++;
        } else if (incomingSeqNum > this.snd_start) {
            System.out.print(":");
            this.snd_start = incomingSeqNum;
            // used for flow control
            this.connected_socket_buffer = trsp.getWindow();
            //System.out.println("updated this.snd_start to: " + this.snd_start);
            // update CWND accordingly

        } else if (incomingSeqNum <= this.snd_start) {
            System.out.println("?");
        }
        // send next window when all packets of current window have been acknowledged
        /*
        if (this.state == State.ESTABLISHED && this.snd_not_ack == this.snd_start && this.snd_start != 0) {
            sendBuff();
        }
         */
    }

    // TLS handshake functions
    private void handleHello(int destAddr, int srcAddr, Transport trsp) {
        int type = trsp.getType();
        if (type == Transport.CLIENT_HELLO) {
            System.out.println("CLIENT_HELLO");
        }
        else {
            System.out.println("SERVER_HELLO");
        }
        // notify secure socket that hello was received
        this.secureSock.onHello(trsp);
    }

    private void handleAuthenticate(Transport trsp) {
        System.out.println("SERVER_AUTHENTICATE");
        this.secureSock.checkAuthentication(trsp);
    }

    private void handleHandshakeFinished(Transport trsp) {
        int type = trsp.getType();
        if (type == Transport.CLIENT_HANDSHAKE_FINISHED) {
            System.out.println("CLIENT_HANDSHAKE_FINISHED");
        }
        else {
            System.out.println("SERVER_HANDSHAKE_FINISHED");
        }
        System.out.println("Key agreement reached: " + this.secureSock.getSecretKey());
    }
    // end TLS handshake functions


    /**
     * Bind a socket to a local port
     *
     * @param localPort int local port number to bind the socket to
     * @return int 0 on success, -1 otherwise
     */
    public int bind(int localPort) {
        if (this.tcpMan.portNotInUse(localPort)) {
            this.srcPort = localPort;
            return 0;
        }
        return -1;
    }

    /**
     * Listen for connections on a socket
     * @param backlog int Maximum number of pending connections
     * @return int 0 on success, -1 otherwise
     */
    public int listen(int backlog) {
        if (this.state == State.JUST_CREATED && this.srcPort != -1) {
            this.backlog = backlog;
            this.state = State.LISTEN;
            return 0;
        }
        return -1;
    }

    /**
     * Accept a connection on a socket
     *
     * @return TCPSock The first established connection on the request queue
     */
    public TCPSock accept() {
        return null;
    }

    public boolean isConnectionPending() {
        return (state == State.SYN_SENT);
    }

    public boolean isClosed() {
        return (state == State.CLOSED);
    }

    public boolean isConnected() {
        return (state == State.ESTABLISHED);
    }

    public boolean isClosurePending() {
        return (state == State.SHUTDOWN);
    }

    /**
     * Initiate connection to a remote socket
     *
     * @param destAddr int Destination node address
     * @param destPort int Destination port
     * @return int 0 on success, -1 otherwise
     */
    public int connect(int destAddr, int destPort) {
        if (this.state == State.JUST_CREATED && this.srcPort != -1) {
            this.dstAddr = destAddr;
            this.dstPort = destPort;
            //this.buffer = new byte[10000];
            this.state = State.SYN_SENT;
            connectWithTimer();
            //this.seqNum = 0;
            return 0;
        }
        // set timer

        return -1;
    }

    public void connectWithTimer() {
        if (this.state == State.SYN_SENT) {
            this.tcpMan.send(this.srcAddr, this.dstAddr, this.srcPort, this.dstPort, Transport.SYN, new byte[0], this.rcv_end, 0);

            try {
                Method connect = Callback.getMethod("connectWithTimer", this, (String[]) null);
                Callback callback = new Callback(connect, this, (Object[]) null);
                this.tcpMan.startTimer(1000, callback);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Error connecting or setting timer!");
                System.exit(1);
            }
        }
    }

    /**
     * Initiate closure of a connection (graceful shutdown)
     */
    public void close() {
        System.out.println("trying to close socket " + this.sock_id);
        if (this.state == State.LISTEN) {
            // remove all sockets from establishedSockets queue
            while (!this.establishedSockets.isEmpty()) {
                TCPSock remove =  this.establishedSockets.remove();
                this.tcpMan.removeSocket(remove);
            }
            //System.out.println("CLOSED listening socket");
            this.state = State.CLOSED;
        } else if (this.state == State.ESTABLISHED) {
            // double-check!
            this.tcpMan.send(this.srcAddr, this.dstAddr, this.srcPort, this.dstPort, Transport.FIN, new byte[0], this.snd_start, 0);
            if (this.snd_start == this.snd_end) {
                this.state = State.CLOSED;
                //System.out.println("CLOSED established socket");
            } else {
                //System.out.println("SHUTDOWN established socket");
                this.state = State.SHUTDOWN;
            }
        } else if (this.state != State.SHUTDOWN) {
            //this.state = State.CLOSED;
            //this.state = State.CLOSED;
        }
    }

    /**
     * Release a connection immediately (abortive shutdown)
     */
    public void release() {
        this.close();
        this.tcpMan.removeSocket(this);
    }

    /**
     * Write to the socket up to len bytes from the buffer buf starting at
     * position pos.
     *
     * @param buf byte[] the buffer to write from
     * @param pos int starting position in buffer
     * @param len int number of bytes to write
     * @return int on success, the number of bytes written, which may be smaller
     *             than len; on failure, -1
     */
    public int write(byte[] buf, int pos, int len) {
        int i;
        for (i = 0; i < len && i < SND_BUFF_SIZE; i++) {
            //if (this.snd_end + i % BUFF_SIZE >= this.snd_start + i % BUFF_SIZE) break;
            this.snd_buff[this.snd_end + i] = buf[pos + i];
        }
        this.snd_end += i;
        this.sendBuff();
        return i;
    }

    public void sendBuff() {
        /*
        if (this.state != State.ESTABLISHED || this.snd_buff == null) {
            return;
        }
         */
        int outLen = MSS;
        //= Math.min(this.snd_end - this.snd_start, MSS);
        //System.out.println("sendBuff(): snd_start: " + this.snd_start + " snd_not_ack: " + this.snd_not_ack);
        for (this.snd_not_ack = this.snd_start; this.snd_not_ack < this.snd_end; this.snd_not_ack += outLen) {
            outLen = send_segment(this.snd_not_ack);
        }
        //this.snd_not_ack -= outLen;
        this.initiate_send_timer();
       // System.arraycopy(this.snd_buff, this.snd_start, outBuff, 0, outLen);
       // this.tcpMan.send(this.srcAddr, this.dstAddr, this.srcPort, this.dstPort, Transport.DATA, outBuff, this.seqNum);
    }

    public int send_segment(int seqNum) {
        //int outLen = Math.min(this.snd_end - seqNum, MSS);
        int outLen = MSS;
        // consider remaining available space in connected socket for flow control
        //if (this.connected_socket_buffer != -1) outLen = Math.min(outLen, this.connected_socket_buffer);
        byte[] outBuff = new byte[outLen];
        System.arraycopy(this.snd_buff, seqNum, outBuff, 0, outLen);
        //System.out.println("sending DATA! srcAddr: " + this.srcAddr + " srcPort: " +  this.srcPort + " dstAddr: " + this.dstAddr +  " dstPort: " + this.dstPort);
        //System.out.println("Sending data with seqNum / this.snd_not_ack " + seqNum + " of length " + outLen);
        this.tcpMan.send(this.srcAddr, this.dstAddr, this.srcPort, this.dstPort, Transport.DATA, outBuff, seqNum, 0);
        // move from Shutdown to Closed, might have to adjust this
        //if (this.state == State.SHUTDOWN && this.snd_start == this.snd_end) this.state = State.CLOSED;
        return outLen;
    }

    public void initiate_send_timer() {
        try {
            Method connect = Callback.getMethod("send_again", this, (String[]) null);
            Callback callback = new Callback(connect, this, (Object[]) null);
            this.tcpMan.startTimer(1000, callback);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error initiating timer on send!");
            System.exit(1);
        }
    }

    public void send_again() {
        if (this.snd_start < this.snd_end) {
            int outLen = 0;
            int i;
            for (i = this.snd_start; i < this.snd_end; i += outLen) {
                //System.out.println("resending data with seqNum  " + i);
                System.out.print("!");
                outLen = send_segment(i);
            }
            initiate_send_timer();
        }
    }

    /**
     * Read from the socket up to len bytes into the buffer buf starting at
     * position pos.
     *
     * @param buf byte[] the buffer
     * @param pos int starting position in buffer
     * @param len int number of bytes to read
     * @return int on success, the number of bytes read, which may be smaller
     *             than len; on failure, -1
     */
    public int read(byte[] buf, int pos, int len) {
        int i;
        for (i = 0; i < len; i++) {
            if (this.rcv_start + i >= this.rcv_end) break;
            buf[pos + i] = this.rcv_buff[this.rcv_start + i];
        }
        this.rcv_start += i;
        if (this.rcv_start == this.rcv_end) this.state = State.CLOSED;
        this.rcv_avail += i;
        return i;
    }

    public int getSrcPort() { return this.srcPort; }
    public int getSrcAddr() { return this.srcAddr; }
    public int getDstPort() { return this.dstPort; }
    public int getDstAddr() { return this.dstAddr; }
    public void setDstAddr(int dstAddr) { this.dstAddr = dstAddr; }
    public void setDstPort(int dstPort) { this.dstPort = dstPort; }
    public void setSrcAddr(int srcAddr) { this.srcAddr = srcAddr; }
    public void setSrcPort(int srcPort) { this.srcPort = srcPort; }
    public void setState(State state) { this.state = state; }
    public int getId() { return this.sock_id; }

    public void print() {
        System.out.println(this.srcAddr + ":" + this.srcPort + " " + this.dstAddr + ":" + this.dstPort);
    }

    /*
     * End of socket API
     */
}
