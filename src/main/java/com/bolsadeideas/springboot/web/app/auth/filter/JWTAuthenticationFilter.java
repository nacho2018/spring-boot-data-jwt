package com.bolsadeideas.springboot.web.app.auth.filter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import com.bolsadeideas.springboot.web.app.models.entities.Usuario;
import com.bolsadeideas.springboot.web.app.service.IJWTService;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.security.Keys;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter{


	private AuthenticationManager authenticationManager;
	private IJWTService jwtService;
	
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, IJWTService jwtService) {
		this.authenticationManager = authenticationManager;
		this.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
		this.jwtService = jwtService;
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		String username = obtainUsername(request);
		String password = obtainPassword(request);
		
		logger.info(String.format("Datos de entrada parametricos : username %s, password %s", username, password));

		if (username == null) {
			username = "";
		}

		if (password == null) {
			password = "";
		}
		
		if (StringUtils.isEmpty(username) && StringUtils.isEmpty(password)) {
			logger.info("Datos no informados por parametro");
		
			//procesa raw data: obtener el flujo y deserializarlo a un objeto Usuario
			try {
				Usuario user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);
				username = user.getUsername();
				password = user.getPassword();
				logger.info(String.format("Datos de entrada json : username %s, password %s", username, password));
			} catch (IOException e) {
				
				logger.info(e.getMessage());
			}
		}

		username = username.trim();
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password); 
		
		return this.authenticationManager.authenticate(authToken);
	}
	
	
	

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		String token = this.jwtService.create(authResult);
	
		response.addHeader("Authorization", "Bearer ".concat(token));
		
		Map<String, Object> body = new HashMap<>();
		body.put("user", (User)authResult.getPrincipal());
		body.put("token", token);
		body.put("mensaje",String.format("Hola usuario %s, se logo con exito!",authResult.getName()));
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		
		response.setContentType("application/json");
		response.setStatus(200);
		
		
	}
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		
		Map<String, Object> body = new HashMap<>();
		body.put("error",String.format("Error de login de usuario ".concat(failed.getMessage()) ));
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		
		response.setContentType("application/json");
		response.setStatus(403);
		
		
	}
	
	

}
