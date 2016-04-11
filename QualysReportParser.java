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

    public String toString(){
    	String salida= "<VulerabilityReport>\n\t"+ reportSummary.toString() +"\t<HostsSummary>\n";
    	for (int i = 0; i<hostSummary.size(); i++){
    		salida = salida +  hostSummary.get(i).toString();
    	}
    	salida = salida + "\t</HostsSummary>\n" + "\t<HostVulnerabilities>\n";
    	for (int i = 0; i<hostVulnerabilities.size(); i++){
    		salida = salida +  hostVulnerabilities.get(i).toString();
    	}
    	salida = salida + "\t</HostVulnerabilities>\n";
		return salida +"</VulerabilityReport>";
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
        boolean isCVEURL =false;
        
        /* Name of the file. */
        /*if (args.length != 1) {
            throw new RuntimeException("The name of the XML file is required!");
        }*/

        //String text = null;

        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();
            //XMLEventReader eventReader = factory.createXMLEventReader(new FileReader(new File(args[0])));
            XMLEventReader eventReader = factory.createXMLEventReader(new FileReader(new File("testHeader.xml")));
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
            String cveurl = "";
            
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
                        } else if (qName.equalsIgnoreCase("IP")){
                        	isIP = true;
                        } else if (qName.equalsIgnoreCase("QID")){
                        	//Separamos QID y QID1 para comprobar cuando pasamos al glosario de las vulnerabilidades
                        	if(!glossary){
                        		isQID = true;
                        	}else{
                        		isQID1 = true;
                        	}
                        } else if (qName.equalsIgnoreCase("PORT")){
                        	isPORT = true;
                        } else if (qName.equalsIgnoreCase("SERVICE")){
                        	isSERVICE = true;
                        } else if (qName.equalsIgnoreCase("PROTOCOL")){
                        	isPROTOCOL = true;
                        } else if (qName.equalsIgnoreCase("GLOSSARY")){
                        	ip = "";qid = "";port = "";protocol = "";service = "";glossary=true;
                        } else if (qName.equalsIgnoreCase("TITLE")){
                        	isTITLE = true;
                        } else if (qName.equalsIgnoreCase("SEVERITY")){
                        	isSEVERITY = true;
                        } else if (qName.equalsIgnoreCase("IMPACT")){
                        	isIMPACT = true;
                        } else if (qName.equalsIgnoreCase("THREAT")){
                        	isTHREAT = true;
                        } else if (qName.equalsIgnoreCase("SOLUTION")){
                        	isSOLUTION = true;
                        } else if (qName.equalsIgnoreCase("CVE_ID")){
                        	isCVE = true;
                        } else if (qName.equalsIgnoreCase("URL") && isCVE){
                        	isCVEURL = true;
                        }
                    break;

                    /* ELEMENT INFO */
                    case XMLStreamConstants.CHARACTERS:
                        Characters characters = event.asCharacters();
                        if (isCOMPANY) {
                            isCOMPANY=false;
                        } else if (isUSERNAME) {
                            isUSERNAME=false;
                        } else if (isGENERATION_DATETIME) {
                            reportTime = characters.getData(); 
                            isGENERATION_DATETIME=false;
                        } else if (isASSET_GROUP_TITLE) {
                            isASSET_GROUP_TITLE=false;
                        } else if (isTOTAL_VULNERABILITIES) {
                            totalNumberOfVulerabilities = characters.getData(); 
                            isTOTAL_VULNERABILITIES=false;
                        } else if (isIP) {
                        	ip = characters.getData();
                        	isIP = false;
                        } else if(isQID){
                        	qid = characters.getData();
                        	isQID =false;
                        } else if (isSERVICE){
                        	service = characters.getData();
                        	isSERVICE = false;
                        } else if (isPORT){
                        	port = characters.getData();
                        	isPORT = false;
                        } else if (isPROTOCOL){
                        	protocol = characters.getData();
                        	isPROTOCOL = false;
                        } else if (isTITLE){
                        	title = characters.getData();
                        	isTITLE = false;
                        } else if (isQID1){
                        	qid1 = characters.getData();
                        	isQID1 = false;
                        } else if (isSEVERITY){
                        	severity = characters.getData();
                        	isSEVERITY = false;
                        } else if (isIMPACT){
                        	impact = characters.getData();
                        	isIMPACT = false;
                        } else if(isTHREAT){
                        	threat = characters.getData();
                        	isTHREAT = false;
                        } else if(isSOLUTION){
                        	solution = characters.getData();
                        	isSOLUTION = false;
                        } else if(isCVEURL){
                        	cveurl = characters.getData();
                        	isCVEURL = false;
                        	isCVE = false;
                        }
                    break;

                    /* ELEMENT END */
                    case XMLStreamConstants.END_ELEMENT:
                    	EndElement endElement = event.asEndElement();
                        String endEl = endElement.getName().getLocalPart();
                        if(endEl.equalsIgnoreCase("HEADER")){
                        	qrp.reportSummary.getTs().setReportTime(reportTime);
                        	qrp.reportSummary.getSvs().setTotalNumberOfVulnerabilities(totalNumberOfVulerabilities);
                        } else if (endEl.equalsIgnoreCase("IP")){
                        	HostInfo hostInfo = new HostInfo(ip);
                        	if(!qrp.hostSummary.contains(hostInfo)){
                        		qrp.hostSummary.add(hostInfo);
                        	}
                        } else if(endEl.equalsIgnoreCase("VULN_INFO")){
                        	SingleVulnerability sv = new SingleVulnerability(qid);
                        	sv.getHostIP().add(ip);
                        	sv.setPortNumber(port);
                        	sv.setServiceName(service);
                        	//REVISAR EL BID
                        	sv.setBID(qid);//NO VA AQUI EL BID
                        	if(qrp.hostVulnerabilities.isEmpty()){	                        	
	                        	qrp.hostVulnerabilities.add(sv);
                        	}else{
                        		boolean flag = false;
                        		for(int i = 0; i< qrp.hostVulnerabilities.size(); i++){
                        			if(qrp.hostVulnerabilities.get(i).getQID().equals(qid)){
                        				qrp.hostVulnerabilities.get(i).getHostIP().add(ip);
                        				flag = true;
                        				break;
                        			}
                        		}
                        		if (!flag){
                        			qrp.hostVulnerabilities.add(sv);
                        		}
                        	}
                        } else if (endEl.equalsIgnoreCase("VULN_DETAILS")){
                        	for (int i = 0; i< qrp.hostVulnerabilities.size();i++){
                        		if(qrp.hostVulnerabilities.get(i).getQID().equals(qid1)){
                        			qrp.hostVulnerabilities.get(i).setOriginalDescription(title);
                        			qrp.hostVulnerabilities.get(i).setSeverity(severity);
                        			qrp.hostVulnerabilities.get(i).setOtherRef(impact);
                        			qrp.hostVulnerabilities.get(i).setVulnerabilityDescription(threat);
                        			qrp.hostVulnerabilities.get(i).setSolution(solution);
                        			qrp.hostVulnerabilities.get(i).setCVE(cveurl);
                        			//MIRAR PROTOCOLO, no va en portProtocol
                        			qrp.hostVulnerabilities.get(i).setPortProtocol(protocol);//NO va aqui el protocolo
                        		}
                        	}
                        }
                    break;
                }
            }
        } catch (FileNotFoundException | XMLStreamException e) {
            e.printStackTrace();
        }
        
        
        //Escribimos en el fichero
        try {
			FileWriter fichero = new FileWriter("salida.xml");
			fichero.write(qrp.toString());
			//bw.write();
			fichero.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        
    }

// Print all employees.
//for (Employee employee : employees)
//System.out.println(employee.toString());
}
