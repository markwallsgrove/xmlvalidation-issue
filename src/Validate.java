import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Iterator;

import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

public class Validate {

    private static Schema getXSD() {
        try {
            InputStream xsd = Validate.class.getResourceAsStream("xsd/saml-schema-metadata-2.0.xsd");
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            factory.setResourceResolver(new LSResourceResolver() {
                @Override
                public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
                    InputStream resourceAsStream = Validate.class.getResourceAsStream(systemId);
                    return new XSDInput(publicId, systemId, resourceAsStream);
                }
            });

            return factory.newSchema(new StreamSource(xsd));
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException, SAXException, ParserConfigurationException {
        Schema xsdSchema = Validate.getXSD();
        URL certsURL = new URL("https://ds.aaf.edu.au/distribution/metadata/metadata.aaf.signed.minimal.xml");
        InputStream certsInputStream = certsURL.openStream();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setSchema(xsdSchema);

        Document document = dbf.newDocumentBuilder().parse(certsInputStream);

        // Find Signature element.
        NodeList nl = document.getElementsByTagNameNS(
            XMLSignature.XMLNS, "Signature"
        );

        if (nl.getLength() == 0) {
            System.err.println("No signature element");
            return;
        }

        // Create a DOMValidateContext and specify a KeySelector
        // and document context.
        DOMValidateContext valContext = new DOMValidateContext(
            new X509KeySelector(), nl.item(0)
        );

        // Unmarshal the XMLSignature.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

        try {
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            boolean coreValidity = signature.validate(valContext);
            if (coreValidity == false) {
                System.err.println("Signature failed core validation");
                boolean sv = signature.getSignatureValue().validate(valContext);
                System.out.println("signature validation status: " + sv);
                if (sv == false) {
                    // Check the validation status of each Reference.
                    Iterator i = signature.getSignedInfo().getReferences().iterator();
                    for (int j=0; i.hasNext(); j++) {
                        boolean refValid = ((Reference) i.next()).validate(valContext);
                        System.out.println("ref["+j+"] validity status: " + refValid);
                    }
                }
            } else {
                System.out.println("Signature passed core validation");
            }
        } catch (MarshalException e) {
            e.printStackTrace();
        } catch (XMLSignatureException e) {
            e.printStackTrace();
        }
    }
}