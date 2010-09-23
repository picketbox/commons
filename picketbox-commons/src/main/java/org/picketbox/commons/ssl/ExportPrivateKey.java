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

import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;

import org.picketbox.commons.cipher.Base64;

/**
 * Exports the private key of a certificate.
 * @author Scott.Stark@jboss.org
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @version $Revision: 1 $
 */
public class ExportPrivateKey
{
   public static void main(String args[]) throws Exception
   {
      if (args.length < 2)
      {
         System.err.println("Export the private key of a certificate\n"
               + "Usage: ExportPrivateKey <keystore> <alias> [password]\n"
               + "keystore: location of the keystore\n"
               + "alias: alias under which the certificate is stored\n"
               + "password: password of the keystore. If this argument is not provided it will be prompted");
         System.exit(1);
      }
      char[] pass = null;
      if (args.length == 3)
      {
         pass = args[2].toCharArray();
      }
      else
      {
         Console console = System.console();
         pass = console.readPassword("Enter the password: ");
      }
      ExportPrivateKey myep = new ExportPrivateKey();
      myep.doit(args[0], args[1], pass);
   }

   public void doit(String fileName, String aliasName, char[] pass) throws Exception
   {

      KeyStore ks = KeyStore.getInstance("JKS");

      File certificateFile = new File(fileName);
      ks.load(new FileInputStream(certificateFile), pass);

      KeyPair kp = getPrivateKey(ks, aliasName, pass);

      PrivateKey privKey = kp.getPrivate();

      String b64 = Base64.encodeBytes(privKey.getEncoded());

      System.out.println("Private key:");
      System.out.println("-----BEGIN PRIVATE KEY-----");
      System.out.println(b64);
      System.out.println("-----END PRIVATE KEY-----");
   }

   // From http://javaalmanac.com/egs/java.security/GetKeyFromKs.html

   public KeyPair getPrivateKey(KeyStore keystore, String alias, char[] password)
   {
      try
      {
         // Get private key
         Key key = keystore.getKey(alias, password);
         if (key instanceof PrivateKey)
         {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();

            // Return a key pair
            return new KeyPair(publicKey, (PrivateKey) key);
         }
      }
      catch (UnrecoverableKeyException e)
      {
      }
      catch (NoSuchAlgorithmException e)
      {
      }
      catch (KeyStoreException e)
      {
      }
      return null;
   }
}