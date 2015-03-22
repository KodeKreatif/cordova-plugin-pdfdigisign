package id.kodekreatif.cordova.PDFDigiSign;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.InterruptedException;

import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.security.KeyChainAliasCallback;
import android.util.Log;

import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.cert.X509CertificateHolder;

import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.cms.CMSSignedGenerator;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.util.Store;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

public class PDFDigiSign extends CordovaPlugin implements SignatureInterface {

  private static BouncyCastleProvider provider = new BouncyCastleProvider();
  private static final String TAG = PDFDigiSign.class.getSimpleName();
  private static final int BUFFER_SIZE = 10240;

  CallbackContext callbackContext = null;
  Context context;

  private PrivateKey privKey;
  private Certificate cert;

  @Override
  public boolean execute(String action, JSONArray data, final CallbackContext callbackContext) throws JSONException {
    if (action.equals("signWithAlias")) {
      context = cordova.getActivity(); 
      final String path = data.getString(0);
      final String alias = data.getString(1);
      final String name = data.getString(2);
      final String location = data.getString(3);
      final String reason = data.getString(4);
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
            try {
              signWithAlias(path, alias, 
                  name, location, reason);
              callbackContext.success(); // Thread-safe.
            }
            catch (Exception e)
            {
              e.printStackTrace();
              callbackContext.error(-1); // Thread-safe.
            }
        }
      });
      return true;
    } else {
      return false;
    }
  }


  public void signWithAlias(final String path, final String alias, final String name, final String location, final String reason) throws IOException, InterruptedException, KeyChainException 
  {
    byte[] buffer = new byte[BUFFER_SIZE];

    this.callbackContext = callbackContext;
    privKey = KeyChain.getPrivateKey(context, alias);
    Certificate[] chain = KeyChain.getCertificateChain(context, alias);
    cert = chain[0];
    File document = new File(path);

    if (!(document != null && document.exists()))
      new RuntimeException("");

    File outputDocument = new File(document.getPath() + ".signed.pdf");
    FileOutputStream fos = new FileOutputStream(outputDocument);

    PDDocument doc = PDDocument.load(document);

    PDSignature signature = new PDSignature();
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); 
    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
    signature.setName(name);
    signature.setLocation(location);
    signature.setReason(reason);
    signature.setSignDate(Calendar.getInstance());
    doc.addSignature(signature, this);
    doc.saveIncremental(fos);
    doc.close();

    File resultDocument = new File(path);
    File removeDocument = new File(document.getPath() + ".unsigned.pdf");

    document.renameTo(removeDocument);
    outputDocument.renameTo(resultDocument);

    return;
  }


  @Override
  public byte[] sign(InputStream content) throws IOException 
  {
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    PDFDigiSignData input = new PDFDigiSignData(content);
    List<Certificate> certs = new ArrayList<Certificate>();
    certs.add(cert);

    try
    {
      Store certStore = new JcaCertStore(certs);

      org.spongycastle.asn1.x509.Certificate x509Cert =
        org.spongycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));

      ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").build(privKey);
      gen.addSignerInfoGenerator(
               new JcaSignerInfoGeneratorBuilder(
               new JcaDigestCalculatorProviderBuilder().build())
               .build(sha256Signer, new X509CertificateHolder(x509Cert)));

      gen.addCertificates(certStore);
      CMSSignedData signedData = gen.generate(input, false);
      return signedData.getEncoded();
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    throw new RuntimeException("Signing error, look at the stack trace");
  }
}


