package qualysreportparser;

public class HostInfo {

    private String ip;

    public HostInfo(String ip) {
        this.ip = ip;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    @Override
    public String toString() {
        return "\t\t<HostInfo>\n"
                + "\t\t\t<HostIP>" + ip + "</HostIP>\n"
                + "\t\t</HostInfo>\n";
    }

}
