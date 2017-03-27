package org.sonatype.nexus.examples.url;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.apache.shiro.authc.credential.SimpleCredentialsMatcher;

public class EmagizNormalizingCredentialsMatcher extends SimpleCredentialsMatcher {

	@Override
	protected boolean equals(Object tokenCredentials, Object accountCredentials) {
		boolean equals = super.equals(tokenCredentials, accountCredentials);
            
        if (equals == false)	{
        	if (isByteSource(tokenCredentials) && isByteSource(accountCredentials)) {
                byte[] tokenBytes = toBytes(tokenCredentials);
                byte[] accountBytes = toBytes(accountCredentials);
                
            	tokenCredentials = normalizeToNotUrlEncoded(tokenBytes);
            	accountCredentials = normalizeToNotUrlEncoded(accountBytes);
            	
            	equals = tokenCredentials.equals(accountCredentials);
        	}
        }
        
        return equals;
	}

	private String normalizeToNotUrlEncoded(byte[] credentialsBytes) {
		String normalizedCredential = new String(credentialsBytes);
		
		if (normalizedCredential.indexOf('%') > -1)	{
			try {
				normalizedCredential = URLDecoder.decode(normalizedCredential, StandardCharsets.UTF_8.name());
			} catch (UnsupportedEncodingException e) {
				// Just use the old one, this should never happen
			}
		}
		
		return normalizedCredential ;
	}

}
