import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;

import com.itextpdf.text.pdf.*;
import com.itextpdf.text.pdf.security.PdfPKCS7;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.tsp.TimeStampToken;

import sun.security.provider.certpath.OCSP;
import sun.security.provider.certpath.OCSP.RevocationStatus;
import sun.security.provider.certpath.OCSP.RevocationStatus.CertStatus;

public class ValidatePDFSignedByDNIe {

	/**
	 * @param args
	 * @throws IOException 
	 * @throws URISyntaxException 
	 * @throws CertPathValidatorException 
	 * @throws CertificateException 
	 */
	public static void main(String[] args) throws IOException,
													 URISyntaxException,
													 CertPathValidatorException, CertificateException {
		
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		CertificateFactory cf = CertificateFactory.getInstance("x509");
		
    	InputStream inStream = Class.class.getResourceAsStream("/resources/ACRAIZ-SHA2.pem");
		X509Certificate rootCert = (X509Certificate) cf.generateCertificate(inStream);
		
    	inStream = Class.class.getResourceAsStream("/resources/AVDNIEFNMTSHA2.cer");
		X509Certificate ocspCert = (X509Certificate) cf.generateCertificate(inStream);

		URI ocspServer = new URI("http://ocsp.dnie.es");

		PdfReader reader = new PdfReader(args[0]);
		AcroFields af = reader.getAcroFields();
		ArrayList<String> names = af.getSignatureNames();
		for (String name : names) {
			PdfPKCS7 pk = af.verifySignature(name);
			Calendar cal = pk.getSignDate();
			TimeStampToken ts = pk.getTimeStampToken();
		    if (ts != null)
		        cal = pk.getTimeStampDate(); // we change sign date to the time stamp
		    if (!pk.isTsp() && ts != null) { // there is time stamp token and it isn't PAdES-LTV
		        try {
					// if could'n verify the time stamp, we will discard the signature
					if (! pk.verifyTimestampImprint() ) {
						continue;
					}
				} catch (GeneralSecurityException e) {
					// Problems with the time stamp
					continue;
				}
		    }			
			X509Certificate pkc[] = (X509Certificate[]) pk.getSignCertificateChain();
			
			// The first certificate in the chain doesn't become to checked partner
			String subject = pkc[0].getSubjectX500Principal().toString();
			if (subject.indexOf(", SERIALNUMBER="+args[1]) < 0)
				continue;
			
			// Let's go to check the certificates in the chain
			for (int i=0;i<pkc.length;i++) {
				X509Certificate signerCert = pkc[i];
				try {
					signerCert.checkValidity();
				} catch (CertificateExpiredException e) {
					// The certificate has expired: breaking the validation chain
					break;
				} catch (CertificateNotYetValidException e) {
					// The certificate isn't yet valid: breaking the validation chain
					break;
				}
				// Let's go to the net!
				RevocationStatus revStatus = OCSP.check(signerCert, rootCert, ocspServer, ocspCert, cal.getTime());
				// How about the revocation status?
				CertStatus cStatus = revStatus.getCertStatus();
				if (cStatus.equals(CertStatus.GOOD)) {
					// print signer certificate
					System.out.println("-----BEGIN SIGNATURE-----");
					try {
						System.out.print(new String(Base64.encodeBase64Chunked(pk.getSigningCertificate().getEncoded())));
					} catch (CertificateEncodingException e) {
						// Unexpected error 
						e.printStackTrace();
					}
					System.out.println("-----END SIGNATURE-----");
					break; // located a GOOD certificate, let's go to the next signature 
				}
			}
		}
	}
}
