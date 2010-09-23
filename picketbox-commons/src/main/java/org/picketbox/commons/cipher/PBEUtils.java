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
package org.picketbox.commons.cipher;

import java.io.Console;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Utility dealing with Password Based Encryption
 * @author Scott.Stark@jboss.org
 * @author Anil.Saldhana@redhat.com
 * @author <a href="mmoyses@redhat.com">Marcus Moyses</a>
 * @since May 25, 2010
 */
public class PBEUtils
{
   public static byte[] encode(byte[] secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
         throws Exception
   {
      Cipher cipher = Cipher.getInstance(cipherAlgorithm);
      cipher.init(Cipher.ENCRYPT_MODE, cipherKey, cipherSpec);
      byte[] encoding = cipher.doFinal(secret);
      return encoding;
   }

   public static String encode64(byte[] secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
         throws Exception
   {
      byte[] encoding = encode(secret, cipherAlgorithm, cipherKey, cipherSpec);
      String b64 = Base64.encodeBytes(encoding);
      return b64;
   }

   public static byte[] decode(byte[] secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
         throws GeneralSecurityException
   {
      Cipher cipher = Cipher.getInstance(cipherAlgorithm);
      cipher.init(Cipher.DECRYPT_MODE, cipherKey, cipherSpec);
      byte[] decode = cipher.doFinal(secret);
      return decode;
   }

   public static String decode64(String secret, String cipherAlgorithm, SecretKey cipherKey, PBEParameterSpec cipherSpec)
         throws GeneralSecurityException, UnsupportedEncodingException
   {
      byte[] encoding = Base64.decode(secret);
      byte[] decode = decode(encoding, cipherAlgorithm, cipherKey, cipherSpec);
      return new String(decode, "UTF-8");
   }

   public static void main(String[] args) throws Exception
   {
      if (args.length < 2)
      {
         System.err.println("Encrypt a password\n"
               + "Usage: PBEUtils <salt> <count> [password]\n"
               + "salt: the Salt\n"
               + "count: the IterationCount\n"
               + "password: the plaintext password that should be encrypted. If this argument is not provided it will be prompted");
         System.exit(1);
      }
      byte[] passwordToEncode = null;
      if (args.length == 3)
      {
         passwordToEncode = args[2].getBytes("UTF-8");
      }
      else
      {
         Console console = System.console();
         char[] pass = console.readPassword("Enter the password: ");
         String passString = new String(pass);
         passwordToEncode = passString.getBytes(); 
      }
      
      byte[] salt = args[0].substring(0, 8).getBytes();
      int count = Integer.parseInt(args[1]);
      char[] password = "somearbitrarycrazystringthatdoesnotmatter".toCharArray();
      PBEParameterSpec cipherSpec = new PBEParameterSpec(salt, count);
      PBEKeySpec keySpec = new PBEKeySpec(password);
      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEwithMD5andDES");
      SecretKey cipherKey = factory.generateSecret(keySpec);
      String encodedPassword = encode64(passwordToEncode, "PBEwithMD5andDES", cipherKey, cipherSpec);
      System.out.println("Encoded password: " + encodedPassword);
   }
}
