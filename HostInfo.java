package qualysreportparser;

import java.net.InetAddress;

public class HostInfo {

    private InetAddress ip;

    public HostInfo() {
        ip = null;
    }

    public InetAddress getIp() {
        return ip;
    }

    public void setIp(InetAddress ip) {
        this.ip = ip;
    }

    @Override
    public String toString() {
        return "<HostInfo>\n"
                + "\t<HostIP>" + ip + "</HostIP>\n"
                + "</HostInfo>";
    }

}
