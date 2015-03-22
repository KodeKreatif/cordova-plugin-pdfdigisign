package id.kodekreatif.cordova.PDFDigiSign;

import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.cms.CMSObjectIdentifiers;
import org.spongycastle.cms.CMSException;
import org.spongycastle.cms.CMSTypedData;

class PDFDigiSignData implements CMSTypedData
{

  InputStream in;
  private static final int BUFFER_SIZE = 10240;
  private final ASN1ObjectIdentifier type;

  public PDFDigiSignData(ASN1ObjectIdentifier type, 
          InputStream is)
  {
    this.type = type;
    in = is;
  }

  public PDFDigiSignData(InputStream is)
  {
    this(new ASN1ObjectIdentifier(CMSObjectIdentifiers.data.getId()), is);
  }

  @Override
  public Object getContent()
  {
    return in;
  }

  @Override
  public void write(OutputStream out) throws IOException, CMSException
  {
    // read the content only one time
    byte[] buffer = new byte[BUFFER_SIZE];
    int c;
    while ((c = in.read(buffer)) != -1)
    {
      out.write(buffer, 0, c);
    }
    in.close();
  }

  @Override
  public ASN1ObjectIdentifier getContentType() {
    return type;
  }
}
