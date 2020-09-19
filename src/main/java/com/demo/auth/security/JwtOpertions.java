package com.demo.auth.security;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import javax.security.sasl.AuthenticationException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.InsufficientAuthenticationException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtOpertions {

	@Value("${jwt.validity.length}")
	private long validityInMilliSeconds;

	@Value("${jwt.signature.algo}")
	private String signatureAlgo;

	public String generateToken(final String id, PrivateKey privateKey) throws AuthenticationException {
		String token = null;
		try {

			Claims claims = Jwts.claims().setSubject(id);
			Date now = new Date();
			Date validuty = new Date(now.getTime() + this.validityInMilliSeconds);
			token = Jwts.builder().setClaims(claims).setIssuedAt(now).setExpiration(validuty).setIssuer("WANGS")
					.signWith(SignatureAlgorithm.valueOf(this.signatureAlgo), privateKey).compact();

		} catch (Exception e) {
			throw new InsufficientAuthenticationException("Issue with token generation");
		}

		return token;

	}

	public void validateTokenSign(String token, PublicKey key) throws AuthenticationException {
		try {
			Jwts.parser().setSigningKey(key).parseClaimsJws(token);
		} catch (Exception e) {
			throw new InsufficientAuthenticationException("Invalid Jwt Token");
		}
	}

	public JwtDetails getJwtDetails(String token, PublicKey key) throws AuthenticationException {
		String id = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().getSubject();
		String issuer = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().getIssuer();
		String getIssuedDate = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody().getIssuedAt()
				.toString();
		return new JwtDetails(token, id, issuer, getIssuedDate);
	}

	public boolean validateIddWithToken(String uri, String id) throws AuthenticationException {
		String newUri = uri;
		boolean isTokenValidWithId = false;
		if (newUri.contains("?")) {
			newUri = newUri.substring(0, uri.indexOf('?'));
		}
		String[] tmp = newUri.split("/");
		String reqId = tmp[tmp.length - 1];
		if (!id.equalsIgnoreCase(reqId)) {
			throw new InsufficientAuthenticationException("Token and Id mismatch");
		} else {
			isTokenValidWithId = true;
		}

		return isTokenValidWithId;
	}

}
