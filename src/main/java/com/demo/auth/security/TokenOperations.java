package com.demo.auth.security;

import javax.security.sasl.AuthenticationException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

@Component
public class TokenOperations {
	
	private static final Logger logger=LogManager.getLogger(TokenOperations.class);
	
	public void validateTokenHistory(JwtDetails details) throws AuthenticationException {
		logger.info("Valid token present for Id" + details.getId());
	}
	

}
