package qualysreportparser;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.ArrayList;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

public class QualysReportParser {

    private ArrayList<HostInfo> hostSummary;
    private ArrayList<SingleVulnerability> hostVulnerabilities;
    private ReportSummary reportSummary;

    public QualysReportParser() {
        hostSummary = new ArrayList<>();
        hostVulnerabilities = new ArrayList<>();
        reportSummary = new ReportSummary();
    }

    public static void main(String[] args) throws FileNotFoundException,
            XMLStreamException {
        boolean isASSET_DATA_REPORT = false;
        boolean isHEADER = false;
        boolean isCOMPANY = false;
        boolean isUSERNAME = false;
        boolean isGENERATION_DATETIME = false;
        boolean isTEMPLATE = false;
        boolean isTARGET = false;
        boolean isUSER_ASSET_GROUPS = false;
        boolean isASSET_GROUP_TITLE = false;
        boolean isCOMBINED_IP_LIST = false;
        boolean isRANGE = false;
        boolean isSTART = false;
        boolean isEND = false;
        boolean isRISK_SCORE_SUMMARY = false;
        boolean isTOTAL_VULNERABILITIES = false;
        boolean isAVG_SECURITY_RISK = false;
        boolean isBUSINESS_RISK = false;

        /* Name of the file. */
        if (args.length != 1) {
            throw new RuntimeException("The name of the XML file is required!");
        }

        String text = null;

        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            XMLEventReader eventReader = factory.createXMLEventReader(new FileReader(new File(args[0])));

            while (eventReader.hasNext()) {
                XMLEvent event = eventReader.nextEvent();

                switch (event.getEventType()) {

                    /* NEW ELEMENT */
                    case XMLStreamConstants.START_ELEMENT:
                        StartElement startElement = event.asStartElement();
                        String qName = startElement.getName().getLocalPart();

                        if (qName.equalsIgnoreCase("ASSET_DATA_REPORT")) {
                            //System.out.println("ASSET_DATA_REPORT");
                            isASSET_DATA_REPORT = true;

                        } else if (qName.equalsIgnoreCase("HEADER")) {
                            //System.out.println("HEADER");
                            isHEADER = true;

                        } else if (qName.equalsIgnoreCase("COMPANY")) {
                            //System.out.println("COMPANY");
                            isCOMPANY = true;

                        } else if (qName.equalsIgnoreCase("USERNAME")) {
                            //System.out.println("USERNAME");
                            isUSERNAME = true;

                        } else if (qName.equalsIgnoreCase("GENERATION_DATETIME")) {
                            //System.out.println("GENERATION_DATETIME");
                            isGENERATION_DATETIME = true;

                        } else if (qName.equalsIgnoreCase("TEMPLATE")) {
                            //System.out.println("TEMPLATE");
                            isTEMPLATE = true;

                        } else if (qName.equalsIgnoreCase("TARGET")) {
                            //System.out.println("TARGET");
                            isTARGET = true;

                        } else if (qName.equalsIgnoreCase("USER_ASSET_GROUPS")) {
                            //System.out.println("USER_ASSET_GROUPS");
                            isUSER_ASSET_GROUPS = true;

                        } else if (qName.equalsIgnoreCase("ASSET_GROUP_TITLE")) {
                            //System.out.println("ASSET_GROUP_TITLE");
                            isASSET_GROUP_TITLE = true;

                        } else if (qName.equalsIgnoreCase("COMBINED_IP_LIST")) {
                            //System.out.println("COMBINED_IP_LIST");
                            isCOMBINED_IP_LIST = true;

                        } else if (qName.equalsIgnoreCase("RANGE")) {
                            //System.out.println("RANGE");
                            isRANGE = true;

                        } else if (qName.equalsIgnoreCase("START")) {
                            //System.out.println("START");
                            isSTART = true;

                        } else if (qName.equalsIgnoreCase("END")) {
                            //System.out.println("END");
                            isEND = true;

                        } else if (qName.equalsIgnoreCase("RISK_SCORE_SUMMARY")) {
                            //System.out.println("RISK_SCORE_SUMMARY");
                            isRISK_SCORE_SUMMARY = true;

                        } else if (qName.equalsIgnoreCase("TOTAL_VULNERABILITIES")) {
                            //System.out.println("TOTAL_VULNERABILITIES");
                            isTOTAL_VULNERABILITIES = true;

                        } else if (qName.equalsIgnoreCase("AVG_SECURITY_RISK")) {
                            //System.out.println("AVG_SECURITY_RISK");
                            isAVG_SECURITY_RISK = true;

                        } else if (qName.equalsIgnoreCase("BUSINESS_RISK")) {
                            //System.out.println("BUSINESS_RISK");
                            isBUSINESS_RISK = true;

                        }
                        break;

                    /* ELEMENT INFO */
                    case XMLStreamConstants.CHARACTERS:
                        Characters characters = event.asCharacters();
                        if (isASSET_DATA_REPORT) {
                            System.out.println("ASSET_DATA_REPORT");

                        } else if (isHEADER) {
                            System.out.println("HEADER");

                        } else if (isCOMPANY) {
                            System.out.println("COMPANY");

                        } else if (isUSERNAME) {
                            System.out.println("USERNAME");

                        } else if (isGENERATION_DATETIME) {
                            System.out.println("GENERATION_DATETIME");

                        } else if (isTEMPLATE) {
                            System.out.println("TEMPLATE");

                        } else if (isTARGET) {
                            System.out.println("TARGET");

                        } else if (isUSER_ASSET_GROUPS) {
                            System.out.println("USER_ASSET_GROUPS");

                        } else if (isASSET_GROUP_TITLE) {
                            System.out.println("ASSET_GROUP_TITLE");

                        } else if (isCOMBINED_IP_LIST) {
                            System.out.println("COMBINED_IP_LIST");

                        } else if (isRANGE) {
                            System.out.println("RANGE");

                        } else if (isSTART) {
                            System.out.println("START");

                        } else if (isEND) {
                            System.out.println("END");

                        } else if (isRISK_SCORE_SUMMARY) {
                            System.out.println("RISK_SCORE_SUMMARY");

                        } else if (isTOTAL_VULNERABILITIES) {
                            System.out.println("TOTAL_VULNERABILITIES");

                        } else if (isAVG_SECURITY_RISK) {
                            System.out.println("AVG_SECURITY_RISK");

                        } else if (isBUSINESS_RISK) {
                            System.out.println("BUSINESS_RISK");

                        }
                        break;

                    /* ELEMENT END */
                    case XMLStreamConstants.END_ELEMENT:
                        if (isASSET_DATA_REPORT) {
                            isASSET_DATA_REPORT = false;

                        } else if (isHEADER) {
                            isHEADER = false;

                        } else if (isCOMPANY) {
                            isCOMPANY = false;

                        } else if (isUSERNAME) {
                            isUSERNAME = false;

                        } else if (isGENERATION_DATETIME) {
                            isGENERATION_DATETIME = false;

                        } else if (isTEMPLATE) {
                            isTEMPLATE = false;

                        } else if (isTARGET) {
                            isTARGET = false;

                        } else if (isUSER_ASSET_GROUPS) {
                            isUSER_ASSET_GROUPS = false;

                        } else if (isASSET_GROUP_TITLE) {
                            isASSET_GROUP_TITLE = false;

                        } else if (isCOMBINED_IP_LIST) {
                            isCOMBINED_IP_LIST = false;

                        } else if (isRANGE) {
                            isRANGE = false;

                        } else if (isSTART) {
                            isSTART = false;

                        } else if (isEND) {
                            isEND = false;

                        } else if (isRISK_SCORE_SUMMARY) {
                            isRISK_SCORE_SUMMARY = false;

                        } else if (isTOTAL_VULNERABILITIES) {
                            isTOTAL_VULNERABILITIES = false;

                        } else if (isAVG_SECURITY_RISK) {
                            isAVG_SECURITY_RISK = false;

                        } else if (isBUSINESS_RISK) {
                            isBUSINESS_RISK = false;

                        }
                        break;
                }
            }
        } catch (FileNotFoundException | XMLStreamException e) {
            e.printStackTrace();
        }
    }

// Print all employees.
//for (Employee employee : employees)
//System.out.println(employee.toString());
}
