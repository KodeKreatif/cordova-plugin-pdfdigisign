package id.kodekreatif.cordova.PDFDigiSign;

import org.apache.cordova.*;
import org.json.JSONArray;
import org.json.JSONException;

import java.io.ByteArrayInputStream;
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
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;

import android.content.Context;
import android.security.KeyChain;
import android.security.KeyChainException;
import android.security.KeyChainAliasCallback;
import android.util.Log;
import android.os.Environment;

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

import org.spongycastle.util.encoders.Base64;
import id.co.kodekreatif.pdfdigisign.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;


public class PDFDigiSign extends CordovaPlugin {

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
      final String imageBase64 = data.getString(5);
      final byte[] imageData = Base64.decode(imageBase64);
      final int page = data.getInt(6);
      final float x = (float)data.getDouble(7); 
      final float y = (float)data.getDouble(8);
      final float width = (float)data.getDouble(9);
      final float height = (float)data.getDouble(10);
      cordova.getThreadPool().execute(new Runnable() {
        public void run() {
            try {
              signWithAlias(path, alias, 
                  name, location, reason, 
                  imageData, page, x, y, width, height);
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
              Gson gson = new GsonBuilder().create();
              Verificator v = new Verificator(path);
              final PDFDocumentInfo s = v.validate();
              
              String info = gson.toJson(s);
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

  public void signWithAlias(final String path, 
      final String alias, 
      final String name, 
      final String location, 
      final String reason, 
      byte[] imageData,
      int page,
      float x,
      float y,
      float width,
      float height) throws IOException, InterruptedException, KeyChainException 
  {
    byte[] buffer = new byte[BUFFER_SIZE];

    this.callbackContext = callbackContext;
    privKey = KeyChain.getPrivateKey(context, alias);
    Certificate[] chain = KeyChain.getCertificateChain(context, alias);
    File document = new File(path);

    if (!(document != null && document.exists()))
      new RuntimeException("");


    Signature signature = new Signature(chain, privKey);
    File outputPath = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS);
    outputPath.mkdirs();
    if (imageData.length > 0) {
      ByteArrayInputStream image = new ByteArrayInputStream(imageData);
      signature.setVisual(image, page, x, y, width, height);
      System.err.println("page " + page + ":" + x + "," + y + " " + width + "x" + height);
    }
    signature.sign(path, outputPath.getAbsolutePath(), name, location, reason);

    File outputDocument = new File(outputPath.getAbsolutePath() + "/" + document.getName() + ".signed.pdf");
    File resultDocument = new File(path);
    File removeDocument = new File(document.getPath() + ".unsigned.pdf");

    document.renameTo(removeDocument);
    outputDocument.renameTo(resultDocument);

    return;
  }
}


