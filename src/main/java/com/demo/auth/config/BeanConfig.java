package com.demo.auth.config;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.util.ResourceUtils;

@Configuration
@PropertySource("classpath:config/config.properties")
public class BeanConfig {

	@Value("${privateKey.file}")	
	private String privateKey;

	@Value("${publicKey.file}")
	private String publicKey;

	public File getPrivateKey() throws FileNotFoundException {
		return ResourceUtils.getFile(this.privateKey);
	}

	public File getPublicKey() throws FileNotFoundException {
		return ResourceUtils.getFile(this.publicKey);
	}

	@Bean("jwtKeyPair")
	public Map<String, Object> getJwtKeyPair()
			throws NoSuchAlgorithmException, FileNotFoundException, IOException, InvalidKeySpecException {
		Map<String, Object> keys = new HashMap<String, Object>();
		
		byte[] keyBytePublicKey = Files.readAllBytes((ResourceUtils.getFile(this.publicKey)).toPath());
		KeyFactory kfPublicKey = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec specPublicKey = new X509EncodedKeySpec(keyBytePublicKey);
		keys.put("public", kfPublicKey.generatePublic(specPublicKey));

		byte[] keyBytes = Files.readAllBytes((ResourceUtils.getFile(this.privateKey)).toPath());
		KeyFactory factory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		keys.put("private", factory.generatePrivate(spec));

		return keys;
	}

}
