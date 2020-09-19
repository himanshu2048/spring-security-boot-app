package com.demo.auth.security;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class JwtAuthorizationFilter extends AbstractAuthenticationProcessingFilter {

	private RequestOperations requestOperations;
	private JwtOpertions JwtOpertions;

	@Autowired
	@Qualifier("jwtKeyPair")
	private Map<String, Object> jwtKeyPair;

	public JwtAuthorizationFilter(ApplicationContext ctx, RequestOperations requestOperations,
			TokenOperations tokenOperations, final JwtOpertions JwtOpertions) {
		super(getOrRequestMatcher());
		this.requestOperations = requestOperations;
		this.JwtOpertions = JwtOpertions;
	}

	private static RequestMatcher getOrRequestMatcher() {
		return new OrRequestMatcher(getwhiteList());
	}

	private static List<RequestMatcher> getwhiteList() {
		List<RequestMatcher> whiteList = new ArrayList<RequestMatcher>();
		whiteList.add(new RegexRequestMatcher(".api.validation.generateId.*", HttpMethod.GET.name(), false));
		whiteList.add(new RegexRequestMatcher(".api.validation.retrieveId.*", HttpMethod.GET.name(), false));
		return whiteList;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		JwtDetails details = null;

		String header = this.requestOperations.getHeader(request);
		String token = this.requestOperations.getToken(header);

		PublicKey publicKey = (PublicKey) jwtKeyPair.get("public");

		this.JwtOpertions.validateTokenSign(token, publicKey);
		details = this.JwtOpertions.getJwtDetails(token, publicKey);
		this.JwtOpertions.validateIddWithToken(request.getRequestURI(), details.getId());
		IdAuthenticationToken authToken = new IdAuthenticationToken(details.getId());
		SecurityContextHolder.getContext().setAuthentication(authToken);
		PrivateKey privateKey = (PrivateKey) jwtKeyPair.get("private");
		String freshToken = this.JwtOpertions.generateToken(details.getId(), privateKey);
		response.setHeader("Authorization", "Basic " + freshToken);
		return authToken;
	}

	@Override
	public void setAuthenticationManager(final AuthenticationManager manager) {
		super.setAuthenticationManager(manager);
	}

	@Override
	protected void successfulAuthentication(final HttpServletRequest request, HttpServletResponse response,
			final FilterChain chain, final Authentication authResult) throws IOException, ServletException {
		chain.doFilter(request, response);
	}

}
