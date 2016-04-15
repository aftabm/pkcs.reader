package crypto.pkcs.reader;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;

import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Base64;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args )
    {
               
        try 
        {
			//String failedPkcs7Filename = "D:/Workspace/Logs/2014-10-28/fail-payload.pkcs7";
			
			//File file = new File(stream);
			//byte[] base64Data = Files.readAllBytes(file.toPath());
        	
        	
        	//readPkcs7("/aft/mdm-config.pkcs7");
        	
        	decrypt("/aft/mdm-config-EncryptedPayloadContent.pkcs1","/aft/device-ca.key");
	
		} 
        catch (Exception e) 
        {
			e.printStackTrace();
		}  
    }
    
    public static void decrypt(String cipherFilename, String certFilename)
    {
    	System.out.println( "!!!START decrypt!!!" );
    	
    	try
    	{
    		byte[] cipherText = readFileFromClassPath(cipherFilename);
    		byte[] certData = readFileFromClassPath(certFilename);
    		X509Certificate cert = null;
    		
    		BlockCipher blockCipher = new CBCBlockCipher(new DESEngine());
    		
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher( blockCipher);
            cipher.init(false, new KeyParameter(certData));
            
            byte[] plainText = new byte[cipher.getOutputSize(cipherText.length)];
            int tam = cipher.processBytes(cipherText, 0, cipherText.length, plainText, 0);
            
            cipher.doFinal(plainText, tam);
            
            System.out.println( new String (plainText, "UTF-8") );
            
            
/*            CMSEnvelopedDataGenerator dgen = new CMSEnvelopedDataGenerator();
           dgen.addRecipientInfoGenerator( new JceKeyTransRecipientInfoGenerator( cert ).setProvider( "BC" ) );
            
            CMSTypedData typedData = new CMSProcessableByteArray( cipherText );
            
            CMSEnvelopedData envdata = dgen.generate(
                typedData,
                new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC).setProvider("BC").build()
            );
            
            SecureLogger.log(logger, " createEncryptedPkcs7Envelope : after : CMSAlgorithm.DES_EDE3_CBC : ", envdata.getEncoded());*/
            
            
            
            
            
            //File privateKeyFile = new File(certFilename); // private key file in PEM format
            //PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
           // Object object = pemParser.readObject();
            
            
            PEMDecryptorProvider decProv = new    JcePEMDecryptorProviderBuilder().build("password".toCharArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            KeyPair kp;
            if (object instanceof PEMEncryptedKeyPair) {
                kp = converter.getKeyPair(((PEMEncryptedKeyPair) certData).decryptKeyPair(decProv));
            }            
            
            
            
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    	}
    	
    	System.out.println( "!!!END decrypt!!!" );
    }
    
    public static void readPkcs7(String filename)
    {
    	try
    	{
    		System.out.println( "!!!START readPkcs7!!!" );
    		
    		byte[] base64Data = readFileFromClassPath(filename);
    		CMSSignedData pkcs7 = new CMSSignedData(Base64.decode(base64Data));
    		CMSProcessable signedData = pkcs7.getSignedContent();
        
    		System.out.println( new String ((byte[]) signedData.getContent(), "UTF-8") );
    		System.out.println( "!!!END readPkcs7!!!" );
    	}
    	catch(Exception e)
    	{
    		e.printStackTrace();
    	}
    }
    
    
    
    
    public static byte[] readFileFromClassPath(String filename)
    {
    	InputStream stream = App.class.getResourceAsStream(filename);
    	
    	byte[] buffer=null;
    	
    	try 
    	{
			{
				System.out.println("!!!!!!!!!"+filename+ " bytes read = "+ stream.available()+"!!!!!!!!!");
				buffer = new byte[stream.available()];
				stream.read(buffer);
				
				if (stream.available()>0)
					System.err.println("!!!!!!!!!"+filename+ " bytes left = "+ stream.available()+"!!!!!!!!!");
				
				stream.close();				
			}
		} 
    	catch (IOException e) 
    	{
			e.printStackTrace();
		}
    	
    	
    	return buffer;
    }
       
}
