package qualysreportparser;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.EndElement;
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

    @Override
    public String toString() {
        String salida = /*"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n\n"*/"<VulnerabilityReport>\n\t"
                + reportSummary.toString()
                + "\t<HostsSummary>\n";

        for (int i = 0; i < hostSummary.size(); i++) {
            salida += hostSummary.get(i).toString();
        }

        salida += "\t</HostsSummary>\n\t<HostVulnerabilities>\n";

        for (int i = 0; i < hostVulnerabilities.size(); i++) {
            salida += hostVulnerabilities.get(i).toString();
        }

        salida += "\t</HostVulnerabilities>\n</VulerabilityReport>";

        return salida;
    }

    public static void main(String[] args) throws FileNotFoundException,
            XMLStreamException {

        QualysReportParser qrp = new QualysReportParser();
        boolean isCOMPANY = false;
        boolean isUSERNAME = false;
        boolean isGENERATION_DATETIME = false;
        boolean isASSET_GROUP_TITLE = false;
        boolean isTOTAL_VULNERABILITIES = false;
        boolean isIP = false;
        boolean isQID = false;
        boolean isQID1 = false;
        boolean isPORT = false;
        boolean isSERVICE = false;
        boolean isPROTOCOL = false;
        boolean isTITLE = false;
        boolean isSEVERITY = false;
        boolean glossary = false;
        boolean isIMPACT = false;
        boolean isTHREAT = false;
        boolean isSOLUTION = false;
        boolean isCVE = false;
        boolean isCVEID = false;

        /* Name of the file. */
        /*if (args.length != 1) {
            throw new RuntimeException("The name of the XML file is required!");
        }*/
        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            //XMLEventReader eventReader = factory.createXMLEventReader(new FileReader(new File(args[0])));
            XMLEventReader eventReader = factory.createXMLEventReader(new FileReader(new File("Scan_Report_Vulnerabilidades_CPD_TELECITY_Irlanda_ndtex.xml")));
            String reportTime = "";
            String totalNumberOfVulerabilities = "";
            String ip = "";
            String qid = "";
            String qid1 = "";
            String port = "";
            String protocol = "";
            String service = "";
            String title = "";
            String severity = "";
            String impact = "";
            String threat = "";
            String solution = "";
            String cveid = "";
            while (eventReader.hasNext()) {
                XMLEvent event = eventReader.nextEvent();
                switch (event.getEventType()) {

                    /* NEW ELEMENT */
                    case XMLStreamConstants.START_ELEMENT:
                        StartElement startElement = event.asStartElement();
                        String qName = startElement.getName().getLocalPart();
                        if (qName.equalsIgnoreCase("COMPANY")) {
                            isCOMPANY = true;
                        } else if (qName.equalsIgnoreCase("USERNAME")) {
                            isUSERNAME = true;
                        } else if (qName.equalsIgnoreCase("GENERATION_DATETIME")) {
                            isGENERATION_DATETIME = true;
                        } else if (qName.equalsIgnoreCase("ASSET_GROUP_TITLE")) {
                            isASSET_GROUP_TITLE = true;
                        } else if (qName.equalsIgnoreCase("TOTAL_VULNERABILITIES")) {
                            isTOTAL_VULNERABILITIES = true;
                        } else if (qName.equalsIgnoreCase("IP")) {
                            isIP = true;
                        } else if (qName.equalsIgnoreCase("QID")) {
                            if (!glossary) {
                                isQID = true;
                            } else {
                                isQID1 = true;
                            }
                        } else if (qName.equalsIgnoreCase("PORT")) {
                            isPORT = true;
                        } else if (qName.equalsIgnoreCase("SERVICE")) {
                            isSERVICE = true;
                        } else if (qName.equalsIgnoreCase("PROTOCOL")) {
                            isPROTOCOL = true;
                        } else if (qName.equalsIgnoreCase("GLOSSARY")) {
                            ip = "";
                            qid = "";
                            port = "";
                            protocol = "";
                            service = "";
                            glossary = true;
                        } else if (qName.equalsIgnoreCase("TITLE")) {
                            isTITLE = true;
                        } else if (qName.equalsIgnoreCase("SEVERITY")) {
                            isSEVERITY = true;
                        } else if (qName.equalsIgnoreCase("IMPACT")) {
                            isIMPACT = true;
                        } else if (qName.equalsIgnoreCase("THREAT")) {
                            isTHREAT = true;
                        } else if (qName.equalsIgnoreCase("SOLUTION")) {
                            isSOLUTION = true;
                        } else if (qName.equalsIgnoreCase("CVE_ID")) {
                            isCVE = true;
                        } else if (qName.equalsIgnoreCase("ID") && isCVE) {
                            isCVEID = true;
                        }
                        break;

                    /* ELEMENT INFO */
                    case XMLStreamConstants.CHARACTERS:
                        Characters characters = event.asCharacters();
                        if (isCOMPANY) {
                            isCOMPANY = false;
                        } else if (isUSERNAME) {
                            isUSERNAME = false;
                        } else if (isGENERATION_DATETIME) {
                            reportTime = characters.getData();
                            isGENERATION_DATETIME = false;
                        } else if (isASSET_GROUP_TITLE) {
                            isASSET_GROUP_TITLE = false;
                        } else if (isTOTAL_VULNERABILITIES) {
                            totalNumberOfVulerabilities = characters.getData();
                            isTOTAL_VULNERABILITIES = false;
                        } else if (isIP) {
                            ip = characters.getData();
                            isIP = false;
                        } else if (isQID) {
                            qid = characters.getData();
                            isQID = false;
                        } else if (isSERVICE) {
                            service = characters.getData();
                            isSERVICE = false;
                        } else if (isPORT) {
                            port = characters.getData();
                            isPORT = false;
                        } else if (isPROTOCOL) {
                            protocol = characters.getData();
                            isPROTOCOL = false;
                        } else if (isTITLE) {
                            title = characters.getData();
                            isTITLE = false;
                        } else if (isQID1) {
                            qid1 = characters.getData();
                            isQID1 = false;
                        } else if (isSEVERITY) {
                            severity = characters.getData();
                            isSEVERITY = false;
                        } else if (isIMPACT) {
                            impact = characters.getData();
                            isIMPACT = false;
                        } else if (isTHREAT) {
                            threat = characters.getData();
                            isTHREAT = false;
                        } else if (isSOLUTION) {
                            solution = characters.getData();
                            isSOLUTION = false;
                        } else if (isCVEID) {
                            cveid = characters.getData();
                            isCVEID = false;
                            isCVE = false;
                        }
                        break;

                    /* ELEMENT END */
                    case XMLStreamConstants.END_ELEMENT:
                        EndElement endElement = event.asEndElement();
                        String endEl = endElement.getName().getLocalPart();
                        if (endEl.equalsIgnoreCase("HEADER")) {
                            qrp.reportSummary.getTs().setReportTime(reportTime);
                            qrp.reportSummary.getSvs().setTotalNumberOfVulnerabilities(totalNumberOfVulerabilities);
                        } else if (endEl.equalsIgnoreCase("IP")) {
                            HostInfo hostInfo = new HostInfo(ip);
                            if (!qrp.hostSummary.contains(hostInfo)) {
                                qrp.hostSummary.add(hostInfo);
                            }
                        } else if (endEl.equalsIgnoreCase("VULN_INFO")) {
                            SingleVulnerability sv = new SingleVulnerability(qid,port);
                            sv.getHostIP().add(ip);
                            sv.setServiceName(service);
                            sv.setBID(qid);
                            sv.setPortProtocol(protocol);
                            if (qrp.hostVulnerabilities.isEmpty()) {
                                qrp.hostVulnerabilities.add(sv);
                            } else {
                                boolean flag = false;
                                for (int i = 0; i < qrp.hostVulnerabilities.size(); i++) {
                                    if (qrp.hostVulnerabilities.get(i).getQID().equals(qid) && qrp.hostVulnerabilities.get(i).getPortNumber().equals(port)) {
                                        qrp.hostVulnerabilities.get(i).getHostIP().add(ip);
                                        flag = true;
                                        break;
                                    }
                                }
                                if (!flag) {
                                    qrp.hostVulnerabilities.add(sv);
                                }
                            }
                        } else if (endEl.equalsIgnoreCase("VULN_DETAILS")) {
                        	boolean encontrado= false;
                        	boolean encontrado1=false;
                            for (int i = 0; i < qrp.hostVulnerabilities.size(); i++) {
                                if (qrp.hostVulnerabilities.get(i).getQID().equals(qid1)) {
                                    qrp.hostVulnerabilities.get(i).setOriginalDescription(title);
                                    qrp.hostVulnerabilities.get(i).setSeverity(severity);
                                    qrp.hostVulnerabilities.get(i).setOtherRef(impact);
                                    qrp.hostVulnerabilities.get(i).setVulnerabilityDescription(threat);
                                    qrp.hostVulnerabilities.get(i).setSolution(solution);
                                    qrp.hostVulnerabilities.get(i).setCVE(cveid);
                                    
                                    for(int j=0; j< qrp.hostVulnerabilities.get(i).getHostIP().size();j++){
                                    	String hostIP = qrp.hostVulnerabilities.get(i).getHostIP().get(j);
                                    	for(int z = 0; z<qrp.hostSummary.size();z++){
                                    		if(qrp.hostSummary.get(z).equals(hostIP)){
                                    			if(severity.equals("1") || severity.equals("2")){
                                    				qrp.hostSummary.get(z).setInformationSeverity(qrp.hostSummary.get(z).getInformationSeverity()+1);
                                    			}else if(severity.equals("3")){
                                    				qrp.hostSummary.get(z).setLowSeverity(qrp.hostSummary.get(z).getLowSeverity()+1);
                                    			}else if(severity.equals("4")){
                                    				qrp.hostSummary.get(z).setMidSeverity(qrp.hostSummary.get(z).getMidSeverity()+1);
                                    			}else{
                                    				qrp.hostSummary.get(z).setHighSeverity(qrp.hostSummary.get(z).getHighSeverity()+1);
                                    			}
                                    			encontrado1= true;
                                    			break;
                                    		}
                                    	}
                                    	if(encontrado1){
                                			break;
                                		}
                                    }
                                    encontrado = true;
                                    break;
                                }
                            }
                            if(!encontrado){
                            	System.out.println("Nueva vulnerabilidad con severidad: "+severity);
                            	SingleVulnerability sv = new SingleVulnerability(qid1,port);
                                sv.setServiceName(service);
                                sv.setBID(qid);
                                sv.setPortProtocol(protocol);
                                sv.setOriginalDescription(title);
                                sv.setSeverity(severity);
                                sv.setOtherRef(impact);
                                sv.setVulnerabilityDescription(threat);
                                sv.setSolution(solution);
                                sv.setCVE(cveid);
                                qrp.hostVulnerabilities.add(sv);
                            }
                        } else if (endEl.equalsIgnoreCase("TEMPLATE_DETAILS")) {
                        	int information = 0;
                        	int low = 0;
                        	int mid = 0;
                        	int high = 0;
                        	for (int  i = 0; i< qrp.hostVulnerabilities.size(); i++){
                        		if(qrp.hostVulnerabilities.get(i).getSeverity().equals("1") || qrp.hostVulnerabilities.get(i).getSeverity().equals("2")){
                        			information ++;
                        		}else if (qrp.hostVulnerabilities.get(i).getSeverity().equals("3")){
                        			low++;
                        		}else if (qrp.hostVulnerabilities.get(i).getSeverity().equals("4")){
                        			mid++;
                        		}else{
                        			high++;
                        		}
                        	}
                        	qrp.reportSummary.getSvs().setHighSeverityVulnerabilities(String.valueOf(high));
                        	qrp.reportSummary.getSvs().setMediumSeverityVulnerabilities(String.valueOf(mid));
                        	qrp.reportSummary.getSvs().setLowSeverityVulnerabilities(String.valueOf(low));
                        	qrp.reportSummary.getSvs().setInformationalVulnerabilities(String.valueOf(information));
                        	qrp.reportSummary.getSvs().setTotalNumberOfVulnerabilities(String.valueOf(qrp.hostVulnerabilities.size()));
                        }
                        break;
                }
            }
        } catch (FileNotFoundException | XMLStreamException e) {
            e.printStackTrace();
        }

        //Escribimos en el fichero
        try {
            FileWriter fichero = new FileWriter("report_vulnerability.xml");
            fichero.write(qrp.toString());
            //bw.write();
            fichero.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
