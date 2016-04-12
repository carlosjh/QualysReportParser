package qualysreportparser;

public class HostInfo {

    private String ip;
    private int highSeverity;
    private int midSeverity;
    private int lowSeverity;
    private int informationSeverity;
    

    public HostInfo(String ip) {
        this.ip = ip;
        highSeverity=0;
        midSeverity=0;
        lowSeverity=0;
        informationSeverity=0;
    }

    public void sumarInformation(){
    	informationSeverity = this.informationSeverity+1;
    }
    
    public void sumarHigh(){
    	highSeverity = this.highSeverity+1;
    }
    
    public void sumarMid(){
    	midSeverity = this.midSeverity+1;
    }
    
    public void sumarLow(){
    	lowSeverity = this.lowSeverity+1;
    }
    
	public int getHighSeverity() {
		return highSeverity;
	}

	public void setHighSeverity(int highSeverity) {
		this.highSeverity = highSeverity;
	}

	public int getMidSeverity() {
		return midSeverity;
	}

	public void setMidSeverity(int midSeverity) {
		this.midSeverity = midSeverity;
	}

	public int getLowSeverity() {
		return lowSeverity;
	}

	public void setLowSeverity(int lowSeverity) {
		this.lowSeverity = lowSeverity;
	}

	public int getInformationSeverity() {
		return informationSeverity;
	}

	public void setInformationSeverity(int informationSeverity) {
		this.informationSeverity = informationSeverity;
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
                +"\t\t\t<HighSeverityVulnerabilities>"+highSeverity+"</HighSeverityVulnerabilities>\n"
                +"\t\t\t<MediumSeverityVulnerabilities>"+midSeverity+"</MediumSeverityVulnerabilities>\n"
                +"\t\t\t<LowSeverityVulnerabilities>"+lowSeverity+"</LowSeverityVulnerabilities>\n"
                +"\t\t\t<InformationalVulnerabilities>"+informationSeverity+"</InformationalVulnerabilities>\n"
                + "\t\t</HostInfo>\n";
    }

}
