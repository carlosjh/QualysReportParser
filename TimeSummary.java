package qualysreportparser;

public class TimeSummary {

    private String ReportTime;
    private String ScanStartTime;
    private String ScanEndTime;
    private String ScanElapsedTime;

    public TimeSummary() {
    }

    public String getReportTime() {
        return ReportTime;
    }

    public void setReportTime(String ReportTime) {
        this.ReportTime = ReportTime;
    }

    public String getScanStartTime() {
        return ScanStartTime;
    }

    public void setScanStartTime(String ScanStartTime) {
        this.ScanStartTime = ScanStartTime;
    }

    public String getScanEndTime() {
        return ScanEndTime;
    }

    public void setScanEndTime(String ScanEndTime) {
        this.ScanEndTime = ScanEndTime;
    }

    public String getScanElapsedTime() {
        return ScanElapsedTime;
    }

    public void setScanElapsedTime(String ScanElapsedTime) {
        this.ScanElapsedTime = ScanElapsedTime;
    }

    @Override
    public String toString() {
        return "<TimeSummary>\n"
                + "\t<ReportTime>" + ReportTime + "</ReportTime>\n"
                + "\t<ScanStartTime>" + ScanStartTime + "</ScanStartTime>\n"
                + "\t<ScanEndTime>" + ScanEndTime + "</ScanEndTime>\n"
                + "\t<ScanElapsedTime>" + ScanElapsedTime + "</ScanElapsedTime>\n" 
                + "</TimeSummary>";
    }

}
