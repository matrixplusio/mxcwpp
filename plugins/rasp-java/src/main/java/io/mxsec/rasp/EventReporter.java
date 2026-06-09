package io.mxsec.rasp;

import java.io.IOException;
import java.io.OutputStream;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 事件上报 (UDS → Agent 主进程) (P4-1).
 *
 * 协议:
 *   4 字节 BE 长度 + JSON body
 *
 * 失败处理:
 *   - 队列满 → drop oldest (不阻塞业务)
 *   - 连接断 → 后台 reconnect 自动重连
 *   - 永不抛异常给业务代码
 */
public class EventReporter {

    private final String udsPath;
    private final String tenantId;
    private final BlockingQueue<RaspEvent> queue;
    private final AtomicLong droppedCount = new AtomicLong();
    private volatile boolean running;
    private Thread worker;

    public EventReporter(String udsPath, String tenantId) {
        this.udsPath = udsPath;
        this.tenantId = tenantId;
        this.queue = new ArrayBlockingQueue<>(10000);
    }

    /**
     * 入队 (非阻塞, 队列满直接丢弃).
     */
    public void emit(RaspEvent ev) {
        if (!running) return;
        if (!queue.offer(ev)) {
            // 丢弃最老的 + 入新
            queue.poll();
            queue.offer(ev);
            droppedCount.incrementAndGet();
        }
    }

    public void start() {
        running = true;
        worker = new Thread(this::run, "mxsec-rasp-reporter");
        worker.setDaemon(true);
        worker.start();
    }

    public void stop() {
        running = false;
        if (worker != null) worker.interrupt();
    }

    public long getDroppedCount() { return droppedCount.get(); }

    private void run() {
        while (running) {
            try (SocketChannel ch = connect()) {
                if (ch == null) {
                    Thread.sleep(5000);
                    continue;
                }
                OutputStream out = Channels.newOutputStream(ch);
                while (running) {
                    RaspEvent ev = queue.take();
                    if (ev == null) continue;
                    writeFrame(out, ev);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Throwable t) {
                // 连接断 → 重连
                try { Thread.sleep(3000); } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    private SocketChannel connect() {
        try {
            UnixDomainSocketAddress addr = UnixDomainSocketAddress.of(Path.of(udsPath));
            SocketChannel ch = SocketChannel.open(addr);
            ch.configureBlocking(true);
            return ch;
        } catch (IOException e) {
            return null;
        }
    }

    private void writeFrame(OutputStream out, RaspEvent ev) throws IOException {
        ev.tenantId = tenantId;
        byte[] body = ev.toJson().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ByteBuffer header = ByteBuffer.allocate(4);
        header.putInt(body.length);
        out.write(header.array());
        out.write(body);
        out.flush();
    }
}
