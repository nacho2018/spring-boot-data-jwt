package com.bolsadeideas.springboot.web.app.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.servlet.ServletException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.bolsadeideas.springboot.web.app.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service("JWTServiceImpl")
public class JWTServiceImpl implements IJWTService{

	private final String CLAVE_SECRETA = "Alguna_clave_secretasdfiodfioiodf  so  234234  234234  dsfosdifh sdfhsdofh";
	private final String PREFIX_TOKEN = "Bearer ";
	private final Long TOKEN_PERIOD = 3600000L*4;
	private final String PARAM_AUTHORITIES = "authorities";
	
	@Override
	public String create(Authentication auth) throws JsonProcessingException {
		
	String username = ((User)auth.getPrincipal()).getUsername();
		
		SecretKey secretKey = Keys.hmacShaKeyFor(CLAVE_SECRETA.getBytes());
		
		Collection<? extends GrantedAuthority> roles = auth.getAuthorities();
		Claims claims = Jwts.claims();
		claims.put(PARAM_AUTHORITIES,new ObjectMapper().writeValueAsString(roles));
		
		String token = Jwts.builder()
				.setClaims(claims)
				.setSubject(username)
				.signWith(secretKey)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + TOKEN_PERIOD))
				.compact();
		
		return token;
	}

	@Override
	public boolean validate(String token) {
				
		try {
			this.getClaims(token);
			
		}catch(JwtException | IllegalArgumentException e) {
			return false;
		}
		return true;
	}

	@Override
	public Claims getClaims(String token) {
		
		return  Jwts.parser()
			.setSigningKey(CLAVE_SECRETA.getBytes())
			.parseClaimsJws(this.resolve(token))
			.getBody();
	}

	@Override
	public String getUsername(String token) {
		return this.getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws  IOException {
	
		return Arrays.asList(
				new ObjectMapper()
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.readValue(this.getClaims(token).get(PARAM_AUTHORITIES).toString().getBytes(), SimpleGrantedAuthority[].class));
		
	}

	@Override
	public String resolve(String token) {
		if (!StringUtils.isEmpty(token) && token.startsWith(PARAM_AUTHORITIES)) {
			return token.replace(PREFIX_TOKEN, "");
		}
		return "";
		
		
	}

}
