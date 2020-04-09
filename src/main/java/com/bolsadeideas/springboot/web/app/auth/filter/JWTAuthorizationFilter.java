package com.bolsadeideas.springboot.web.app.auth.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.bolsadeideas.springboot.web.app.SimpleGrantedAuthorityMixin;
import com.bolsadeideas.springboot.web.app.service.IJWTService;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter{

	
	private IJWTService jwtService;
	
	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, IJWTService jwtService) {
		super(authenticationManager);
		this.jwtService = jwtService;
	
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		String header = request.getHeader("Authorization");
				
		//debe ser de prefijo Bearer, si no, pasar al siguiente filtro o controller
		if (!requireAuthentication(header) ) {
			chain.doFilter(request, response);
			return;
		}
		
		UsernamePasswordAuthenticationToken authentication = null;
		
		if (this.jwtService.validate(header)) {
			String username = this.jwtService.getClaims(header).getSubject();
			
			Collection<? extends GrantedAuthority> authorities = 
					this.jwtService.getRoles(header);
			authentication = new UsernamePasswordAuthenticationToken(
					username, null, authorities);
			
		}
		//autorizacion al contexto
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
		
		
	}
		
		protected boolean requireAuthentication(String header) {
			
			if(header ==null || !header.startsWith("Bearer")) {
				return false;
			}
			return true;
		}
	
	

}
