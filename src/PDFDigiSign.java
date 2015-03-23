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
import java.lang.StringBuilder;

import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
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

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;

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
    context = cordova.getActivity(); 
    if (action.equals("signWithAlias")) {
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
    } else if (action.equals("validate")) {
      final String path = data.getString(0);
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
            try {
              String info = validate(path);
              if (info == null) {
                callbackContext.error(0);
              } else {
                callbackContext.success(info);
              }
            }
            catch (Exception e)
            {
              e.printStackTrace();
              callbackContext.error(-1); 
            }
        }
      });
      return true;
    } else {

      return false;
    }
  }

  public String getInfoFromCert(final COSDictionary cert) {
    StringBuilder s = new StringBuilder();
    String name = cert.getString(COSName.NAME, "Unknown");
    String location = cert.getString(COSName.LOCATION, "Unknown");
    String reason = cert.getString(COSName.REASON, "Unknown");
    String contactInfo = cert.getString(COSName.CONTACT_INFO, "Unknown");
    String modified = cert.getString(COSName.M);

    s.append("{");
    s.append("\"hasSignature\":true,");
    s.append("\"name\":\"" + name + "\", ");
    s.append("\"modified\": \"" + modified + "\", ");
    s.append("\"location\": \"" + location + "\", ");
    s.append("\"reason\": \"" + reason + "\", ");
    s.append("\"contactInfo\": \"" + contactInfo + "\" ");
    s.append("}");

    COSName subFilter = (COSName) cert.getDictionaryObject(COSName.SUB_FILTER);

    if (subFilter == null) {
      return null;
    }
    return s.toString();
  }

  public String validate(final String path) throws IOException, CertificateException {
    String infoString = null;
    PDDocument document = null;
    try {
      document = PDDocument.load(new File(path));

      COSDictionary trailer = document.getDocument().getTrailer();
      COSDictionary root = (COSDictionary) trailer.getDictionaryObject(COSName.ROOT);
      COSDictionary acroForm = (COSDictionary) root.getDictionaryObject(COSName.ACRO_FORM);
      Log.d(TAG, "acroForm " + path + ": " +(acroForm == null));
      if (acroForm == null) {
        infoString = "{ \"hasSignature\": false}";
        return infoString;
      }
      COSArray fields = (COSArray) acroForm.getDictionaryObject(COSName.FIELDS);

      boolean certFound = false;
      for (int i = 0; i < fields.size(); i ++) {
        COSDictionary field = (COSDictionary) fields.getObject(i);

        COSName type = field.getCOSName(COSName.FT);
        if (COSName.SIG.equals(type)) {
          COSDictionary cert = (COSDictionary) field.getDictionaryObject(COSName.V);
          if (cert != null) {
            infoString = getInfoFromCert(cert);
            certFound = true;
          }
        }

      }
      if (certFound != true) {
        infoString = "{ \"hasSignature\": false}";
      }

    }
    finally {
      if (document != null) {
        document.close();
      }
    }
    return infoString;
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


