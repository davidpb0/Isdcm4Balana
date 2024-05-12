package isdcm4;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.cert.X509Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class SignXACMLPolicy {
    static {
        Init.init();
    }

    public static void main(String[] args) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        Document doc = builder.parse(new FileInputStream("src/support/policy/XACMLPolicyToSign.xml"));

        Element root = doc.getDocumentElement();

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream("keystore.jks"), "admin123".toCharArray());
        Key key = ks.getKey("mykey", "admin123".toCharArray());
        Certificate cert = ks.getCertificate("mykey");

        XMLSignature sig = new XMLSignature(doc, "", XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
        root.appendChild(sig.getElement());

        Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);

        sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);

        sig.addKeyInfo(cert.getPublicKey());
        sig.addKeyInfo((X509Certificate) cert);

        sig.sign((PrivateKey) key);

        FileOutputStream fos = new FileOutputStream("signedPolicy.xml");
        Transformer trans = TransformerFactory.newInstance().newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(fos));
    }
}
