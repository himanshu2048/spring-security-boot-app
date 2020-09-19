package com.demo.auth.config;

import java.util.Collections;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

import com.demo.auth.security.JwtAuthorizationEntryPoint;
import com.demo.auth.security.JwtAuthorizationFilter;
import com.demo.auth.security.JwtOpertions;
import com.demo.auth.security.JwtSuccessHandler;
import com.demo.auth.security.RequestOperations;
import com.demo.auth.security.TokenOperations;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	private static final Logger logger = LogManager.getLogger(WebSecurityConfig.class);

	@Autowired
	private AnonymousAuthenticationProvider authenticationProvider;

	@Bean
	public AuthenticationManager getAuthManager() {
		return new ProviderManager(Collections.singletonList(this.authenticationProvider));
	}

	@Bean
	JwtAuthorizationEntryPoint getJwtAuthorizationEntryPoint() {
		return new JwtAuthorizationEntryPoint();
	}

	@Bean
	AnonymousAuthenticationProvider getAuthenticationProvider() {
		return new AnonymousAuthenticationProvider("ANONYMOUS_KEY");
	}

	@Override
	protected void configure(final HttpSecurity http) throws Exception {

		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.authorizeRequests().antMatchers("/api/validation/generateId", "/api/validation/retrieveId").permitAll()
				.anyRequest().fullyAuthenticated().and()
				.addFilterBefore(authTokenFilter(), AnonymousAuthenticationFilter.class).exceptionHandling()
				.authenticationEntryPoint(getJwtAuthorizationEntryPoint());
		http.httpBasic().disable();
	}

	@Override
	public void configure(final WebSecurity web) {
		web.ignoring().antMatchers("/h2", "/h2/", "/*.html", "/**/*.js");
	}

	private JwtAuthorizationFilter authTokenFilter() throws Exception {
		JwtAuthorizationFilter filter = new JwtAuthorizationFilter(getApplicationContext(), getRequestOperations(),
				getTokenOperations(), getJwtOperation());
		filter.setAuthenticationManager(authenticationManager());
		filter.setAuthenticationSuccessHandler(new JwtSuccessHandler());
		// TODO Auto-generated method stub
		return filter;
	}

	@Bean
	RequestOperations getRequestOperations() {
		return new RequestOperations();
	}

	@Bean
	TokenOperations getTokenOperations() {
		return new TokenOperations();
	}

	@Bean
	JwtOpertions getJwtOperation() {
		return new JwtOpertions();
	}

	@Bean
	public BCryptPasswordEncoder encoder() {
		return new BCryptPasswordEncoder();
	}

}
