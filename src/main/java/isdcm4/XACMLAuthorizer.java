package isdcm4;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.balana.PDP;
import org.wso2.balana.PDPConfig;
import org.wso2.balana.finder.PolicyFinder;
import org.wso2.balana.finder.impl.FileBasedPolicyFinderModule;
import org.xml.sax.InputSource;

public class XACMLAuthorizer {

    private static PDP initializePDP(String policyFilePath) {
        Set<String> policyPaths = new HashSet<>();
        policyPaths.add(policyFilePath);
        PolicyFinder policyFinder = new PolicyFinder();
        FileBasedPolicyFinderModule policyFinderModule = new FileBasedPolicyFinderModule(policyPaths);
        policyFinder.setModules(new HashSet<>(Set.of(policyFinderModule)));

        PDPConfig pdpConfig = new PDPConfig(null, policyFinder, null);
        return new PDP(pdpConfig);
    }


    private static String evaluateRequest(PDP pdp, String requestPath) throws IOException {
        String request = new String(Files.readAllBytes(Paths.get(requestPath)));
        return pdp.evaluate(request);
    }

    private static void saveResponse(String response, String outputPath) throws IOException {
        try (PrintWriter out = new PrintWriter(new FileOutputStream(outputPath))) {
            out.print(response);
        }
    }

    private static void printDecisionAndStatusCode(String response) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(response)));

            NodeList decisionList = doc.getElementsByTagName("Decision");
            String decision = decisionList.item(0).getTextContent();

            NodeList statusCodeList = doc.getElementsByTagName("StatusCode");
            String statusCode = ((Element) statusCodeList.item(0)).getAttribute("Value");

            System.out.println("Decision: " + decision);
            System.out.println("StatusCode: " + statusCode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("Enter a policy number (1-5):");
            int policyNumber = Integer.parseInt(scanner.nextLine());
            String policyFilePath = "src/support/policy/XACMLPolicy" + policyNumber + ".xml";

            System.out.println("Enter a request number (1-9):");
            int requestNumber = Integer.parseInt(scanner.nextLine());
            String requestFilePath = "src/support/requests/XACMLRequest" + requestNumber + ".xml";
            
            long startTime = System.nanoTime();

            PDP pdp = initializePDP(policyFilePath);
            String response = evaluateRequest(pdp, requestFilePath);

            long endTime = System.nanoTime();
            long duration = (endTime - startTime) / 1_000_000;
            System.out.println("Evaluation time: " + duration + " ms");

            printDecisionAndStatusCode(response);
            saveResponse(response, "XACMLContextResponse.xml");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
