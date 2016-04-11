package qualysreportparser;

public class ReportSummary {
    private TimeSummary ts;
    private SecurityVulnerabilitySummary svs;

    public ReportSummary() {
        ts = new TimeSummary();
        svs = new SecurityVulnerabilitySummary();
    }

    public TimeSummary getTs() {
        return ts;
    }

    public void setTs(TimeSummary ts) {
        this.ts = ts;
    }

    public SecurityVulnerabilitySummary getSvs() {
        return svs;
    }

    public void setSvs(SecurityVulnerabilitySummary svs) {
        this.svs = svs;
    }

    @Override
    public String toString() {
        return "<ReportSummary>\n\t" + ts.toString() +"\n\t"+ svs.toString() + "\n\t</ReportSummary>\n";
    }
}
