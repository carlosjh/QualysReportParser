package qualysreportparser;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

public class QualysReportParser {

    private ArrayList<HostInfo> hostSummary;
    private ArrayList<SingleVulnerability> hostVulnerabilities;
    private ReportSummary reportSummary;

    public QualysReportParser() {
        hostSummary = new ArrayList<>();
        hostVulnerabilities = new ArrayList<>();
        reportSummary = new ReportSummary();
    }

    public static void main(String[] args) {
        BufferedReader br = null;

        try {
            String sCurrentLine;
            br = new BufferedReader(new FileReader("report.xml"));

            while ((sCurrentLine = br.readLine()) != null) {
                System.out.println(sCurrentLine);
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (br != null) {
                    br.close();
                }
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}
