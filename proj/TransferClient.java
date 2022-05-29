/**
 * <p>Title: CPSC 433/533 Programming Assignment</p>
 *
 * <p>Copyright: Copyright (c) 2006</p>
 *
 * <p>Company: Yale University</p>
 *
 * @author Hao Wang
 * @version 1.0
 */

/**
 * <p> A transfer client using Fishnet socket API </p>
 */
import java.util.Arrays;

public class TransferClient extends FishThread {
    private SecureSocket sock;
    private long interval;
    private byte[] buf;

    public static final long DEFAULT_CLIENT_INTERVAL = 1000;
    public static final int DEFAULT_BUFFER_SZ = 65536;
    public static final byte[] DUMMY_CONTENT = "Most of the big shore places were closed now and there were hardly any lights except the shadowy, moving glow of a ferryboat across the Sound. And as the moon rose higher the inessential houses began to melt away until gradually I became aware of the old island here that flowered once for Dutch sailors’ eyes—a fresh, green breast of the new world. Its vanished trees, the trees that had made way for Gatsby’s house, had once pandered in whispers to the last and greatest of all human dreams; for a transitory enchanted moment man must have held his breath in the presence of this continent, compelled into an æsthetic contemplation he neither understood nor desired, face to face for the last time in history with something commensurate to his capacity for wonder. And as I sat there, brooding on the old unknown world, I thought of Gatsby’s wonder when he first picked out the green light at the end of Daisy’s dock. He had come a long way to this blue lawn and his dream must have seemed so close that he could hardly fail to grasp it. He did not know that it was already behind him, somewhere back in that vast obscurity beyond the city, where the dark fields of the republic rolled on under the night. Gatsby believed in the green light, the orgastic future that year by year recedes before us. It eluded us then, but that’s no matter—tomorrow we will run faster, stretch out our arms farther... And one fine morning —— So we beat on, boats against the current, borne back ceaselessly into the past.".getBytes();

    // number of bytes to send
    private int amount;
    // starting and finishing time in milliseconds
    private long startTime;
    private long finishTime;
    private int pos;

    public TransferClient(Manager manager, Node node, SecureSocket sock, int amount,
                          long interval, int sz) {
        super(manager, node);
        this.sock = sock;
        this.interval = interval;
        this.buf = new byte[sz];
        this.amount = amount;
        this.startTime = 0;
        this.finishTime = 0;
        this.pos = 0;
        System.out.println("size is: " + sz);
        this.setInterval(this.interval);
    }

    public TransferClient(Manager manager, Node node, SecureSocket sock, int amount) {
        this(manager, node, sock, amount,
             DEFAULT_CLIENT_INTERVAL,
             DEFAULT_BUFFER_SZ);
    }

    public void execute() {
        if (sock.isConnectionPending()) {
            //node.logOutput("connecting...");
            return;
        } else if (sock.isConnected()) {

            if (startTime == 0) {
                // record starting time
                startTime = manager.now();
                node.logOutput("time = " + startTime + " msec");
                node.logOutput("started");
                node.logOutput("bytes to send = " + amount);
            }

            if (amount <= 0) {
                // sending completed, initiate closure of connection
                node.logOutput("time = " + manager.now());
                node.logOutput("sending completed");
                node.logOutput("closing connection...");
                sock.close();
                return;
            }

            //node.logOutput("sending...");
            int index = pos % buf.length;

            if (index == 0) {
                // generate new data
                for (int i = 0; i < buf.length; i++) {
                    buf[i] = (byte) DUMMY_CONTENT[i % DUMMY_CONTENT.length];
                }
            }

            int len = Math.min(buf.length - index, amount);
            // print out what is being send for reference
            System.out.println("************************************************************");
            System.out.println("Sending encryption of the following content in several packages:");
            byte[] byte_content = Arrays.copyOfRange(buf, 0, len);
            String string_content = new String(byte_content);
            System.out.println(string_content);
            System.out.println("************************************************************");
            int count = sock.write(buf, index, len);

            if (count == -1) {
                // on error, release the socket immediately
                node.logError("time = " + manager.now() + " msec");
                node.logError("sending aborted");
                node.logError("position = " + pos);
                node.logError("releasing connection...");
                sock.release();
                this.stop();
                return;
            }

            pos += count;
            amount -= count;

            //node.logOutput("time = " + manager.now());
            //node.logOutput("bytes sent = " + count);
            return;
        } else if (sock.isClosurePending()) {
            //node.logOutput("closing connection...");
            return;
        } else if (sock.isClosed()) {
            finishTime = manager.now();
            node.logOutput("time = " + manager.now() + " msec");
            node.logOutput("connection closed");
            node.logOutput("total bytes sent = " + pos);
            node.logOutput("time elapsed = " +
                           (finishTime - startTime) + " msec");
            node.logOutput("Bps = " + pos * 1000.0 / (finishTime - startTime));
            // release the socket
            sock.release();
            this.stop();
            return;
        }

        node.logError("shouldn't reach here");
        System.exit(1);
    }
}
