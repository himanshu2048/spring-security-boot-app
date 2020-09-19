package com.demo.auth.controller;

import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import javax.security.sasl.AuthenticationException;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.demo.auth.security.JwtOpertions;

@RestController
public class AuthenticationController {

	@Autowired
	@Qualifier("jwtKeyPair")
	private Map<String, Object> jwtKeyPair;
	
	@Autowired
	JwtOpertions operations;

	@GetMapping(path = "/api/validation/generateId/{id}")
	public ResponseEntity<HashMap<String, String>> generateTokenOnId(@PathVariable("id") final String id,
			final HttpServletRequest httpServletRequest) throws AuthenticationException {
         HashMap<String,  String> map=new HashMap<String, String>();
         map.put("id", id);
         PrivateKey privateKey=   (PrivateKey) ((Map) jwtKeyPair.get("jwtKeyPair")).get("private");
         map.put("Authorization", "Basic "+operations.generateToken(id, privateKey));
         return new ResponseEntity<HashMap<String,String>>(map, HttpStatus.OK);
	}

}
