package com.demo.auth.security;


import org.springframework.security.authentication.AbstractAuthenticationToken;

public class IdAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;
	private String id;

	
	 public IdAuthenticationToken(String id) {
		 super(null);
		 this.id=id;
		 super.setAuthenticated(true);
	}
	
	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return null;
	}

	public String getId() {
		return id;
	}

}
