package com.samourai.wallet.bip47.v3;

import org.bitcoinj.core.AddressFormatException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class Util  {

    public static byte[] xor(byte[] b0, byte[] b1)   {

        if(b0.length != b1.length)   {
            return  null;
        }

        byte[] ret = new byte[b0.length];
        int i = 0;
        for (byte b : b0)   {
            ret[i] = (byte)(b ^ b1[i]);
            i++;
        }

        return ret;
    }

    public static byte[] getHMAC(byte[] b0, byte[] b1) throws AddressFormatException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {

        Mac sha512_HMAC = null;
        byte[] mac_data = null;

        try {
            sha512_HMAC = Mac.getInstance("HmacSHA512");
            SecretKeySpec secretkey = new SecretKeySpec(b0, "HmacSHA512");
            sha512_HMAC.init(secretkey);
            mac_data = sha512_HMAC.doFinal(b1);
        }
        catch(InvalidKeyException jse) {
            return null;
        }
        catch(NoSuchAlgorithmException nsae) {
            return null;
        }

        return mac_data;
    }

}
