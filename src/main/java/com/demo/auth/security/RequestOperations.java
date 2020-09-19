package com.demo.auth.security;

import javax.security.sasl.AuthenticationException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Component;

@Component
public class RequestOperations {
	
	
	public String getHeader(final HttpServletRequest request) throws AuthenticationException {
		String header=request.getHeader("Authorization");
		if(null==header || header.startsWith("Basic ")){
			throw new AuthenticationException();
		}
		return header;
	}
	
	
	public String getToken(final String header) throws AuthenticationException {
		String token=header.substring("Basic ".length());
		if(null==token || token.length() <1) {
			throw new AuthenticationException();
		}
		return token;
	}

}
