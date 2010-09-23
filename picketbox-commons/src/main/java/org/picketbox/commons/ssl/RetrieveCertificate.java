/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2010, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors. 
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.picketbox.commons.ssl;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.picketbox.commons.cipher.Base64;

/**
 * RetrieveCertificate connects to a host and retrieves the certificate chain if it is not
 * already trusted by JDK's default truststore.
 * 
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class RetrieveCertificate
{

   public static void main(String[] args) throws Exception
   {
      String host = null;
      int port = 0;
      if (args.length == 1)
      {
         String[] c = args[0].split(":");
         host = c[0];
         port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
      }
      else
      {
         System.err.println("Retrieve a certificate\n"
               + "Usage: RetrieveCertificate <host>[:port]\n"
               + "host: name or IP of the host\n"
               + "port: port to connect. This argument is optional. Default is 443");
         System.exit(1);
      }

      File file = new File("jssecacerts");
      if (file.isFile() == false)
      {
         char SEP = File.separatorChar;
         File dir = new File(System.getProperty("java.home") + SEP + "lib" + SEP + "security");
         file = new File(dir, "jssecacerts");
         if (file.isFile() == false)
         {
            file = new File(dir, "cacerts");
         }
      }
      System.out.println("Loading KeyStore " + file + "...");
      InputStream in = new FileInputStream(file);
      KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
      ks.load(in, "changeit".toCharArray());
      in.close();

      SSLContext context = SSLContext.getInstance("TLS");
      TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(ks);
      X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
      SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
      context.init(null, new TrustManager[]{tm}, null);
      SSLSocketFactory factory = context.getSocketFactory();

      System.out.println("Opening connection to " + host + ":" + port + "...");
      SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
      socket.setSoTimeout(10000);
      try
      {
         System.out.println("Starting SSL handshake...");
         socket.startHandshake();
         socket.close();
         System.out.println();
         System.out.println("No errors, certificate is already trusted");
      }
      catch (SSLException e)
      {
         System.out.println();
         e.printStackTrace(System.out);
      }

      X509Certificate[] chain = tm.chain;
      if (chain == null)
      {
         System.out.println("Could not obtain server certificate chain");
         return;
      }

      System.out.println();
      System.out.println("Server sent " + chain.length + " certificate(s):");
      System.out.println();
      MessageDigest sha1 = MessageDigest.getInstance("SHA1");
      MessageDigest md5 = MessageDigest.getInstance("MD5");
      for (int i = 0; i < chain.length; i++)
      {
         X509Certificate cert = chain[i];
         System.out.println(" " + (i + 1) + " Subject " + cert.getSubjectDN());
         System.out.println("   Issuer  " + cert.getIssuerDN());
         sha1.update(cert.getEncoded());
         System.out.println("   sha1    " + toHexString(sha1.digest()));
         md5.update(cert.getEncoded());
         System.out.println("   md5     " + toHexString(md5.digest()));
         System.out.println();
      }

      System.out.println("Certificates:");
      for (int i = 0; i < chain.length; i++)
      {
         X509Certificate cert = chain[i];
         String b64 = Base64.encodeBytes(cert.getEncoded());

         System.out.println("-----BEGIN CERTIFICATE-----");
         System.out.println(b64);
         System.out.println("-----END CERTIFICATE-----");
      }
   }

   private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

   private static String toHexString(byte[] bytes)
   {
      StringBuilder sb = new StringBuilder(bytes.length * 3);
      for (int b : bytes)
      {
         b &= 0xff;
         sb.append(HEXDIGITS[b >> 4]);
         sb.append(HEXDIGITS[b & 15]);
         sb.append(' ');
      }
      return sb.toString();
   }

   private static class SavingTrustManager implements X509TrustManager
   {

      private final X509TrustManager tm;

      private X509Certificate[] chain;

      SavingTrustManager(X509TrustManager tm)
      {
         this.tm = tm;
      }

      public X509Certificate[] getAcceptedIssuers()
      {
         throw new UnsupportedOperationException();
      }

      public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException
      {
         throw new UnsupportedOperationException();
      }

      public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException
      {
         this.chain = chain;
         tm.checkServerTrusted(chain, authType);
      }
   }

}
