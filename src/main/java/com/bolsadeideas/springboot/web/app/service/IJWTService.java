package com.bolsadeideas.springboot.web.app.service;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import io.jsonwebtoken.Claims;

public interface IJWTService {
	
	public String create(Authentication auth) throws JsonProcessingException ; //fase autenticacion
	public boolean validate(String token); //fase autorizacion
	public Claims getClaims(String token); //fase autorizacion
	public String getUsername(String token); //fase autorizacion
	public Collection<? extends GrantedAuthority> getRoles(String token) throws  IOException; //fase autorizacion
	public String resolve(String token); //fase autorizacion
	
	

}
