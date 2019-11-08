import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class Validate {
    private static final Logger LOGGER = LoggerFactory.getLogger(Validate.class);

    public static final boolean verifySignature(PdfReader pdfReader)
            throws GeneralSecurityException, IOException {
        boolean valid = false;
        AcroFields acroFields = pdfReader.getAcroFields();
        List<String> signatureNames = acroFields.getSignatureNames();
        Security.addProvider(new BouncyCastleProvider());
        if (!signatureNames.isEmpty()) {
            for (String name : signatureNames) {
                if (acroFields.signatureCoversWholeDocument(name)) {
                    PdfPKCS7 pkcs7 = acroFields.verifySignature(name);
                    valid = pkcs7.verify();
                    String reason = pkcs7.getReason();
                    Calendar signedAt = pkcs7.getSignDate();
                    X509Certificate signingCertificate = pkcs7.getSigningCertificate();
                    Principal issuerDN = signingCertificate.getIssuerDN();
                    Principal subjectDN = signingCertificate.getSubjectDN();
                    System.out.println(valid+" "+ " " + signedAt.getTime() + "  "+ reason+ " " + issuerDN + " "+ subjectDN);
                    //LOGGER.info("valid = {}, date = {}, reason = '{}', issuer = '{}', subject = '{}'",valid, signedAt.getTime(), reason, issuerDN, subjectDN);
                    break;
                }
            }
        }
        return valid;
    }

    private static void validate(String name)
            throws IOException, GeneralSecurityException {
        InputStream is = new FileInputStream(name);
        PdfReader reader = new PdfReader(is);
        boolean ok = verifySignature(reader);
        System.out.println("Signature is verified:"+ok);
    }

    public static void main(String[] args) throws Exception {
        validate("C:\\Users\\sshakeer\\Desktop\\pdfs.pdf"); // if placed in resources' root
    }
}
