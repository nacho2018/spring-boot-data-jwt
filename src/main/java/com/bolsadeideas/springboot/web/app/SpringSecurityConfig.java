package com.bolsadeideas.springboot.web.app;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.bolsadeideas.springboot.web.app.auth.filter.JWTAuthenticationFilter;
import com.bolsadeideas.springboot.web.app.auth.filter.JWTAuthorizationFilter;
import com.bolsadeideas.springboot.web.app.auth.handler.LoginSuccessHandler;
import com.bolsadeideas.springboot.web.app.models.service.JpaUserDetailsService;
import com.bolsadeideas.springboot.web.app.service.IJWTService;

@EnableGlobalMethodSecurity(securedEnabled=true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter{

	@Autowired
	private LoginSuccessHandler successHandler;
	
	@Autowired
	private JpaUserDetailsService userDetailsService;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private IJWTService jwtService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		//public routes for anonimous and registered users
		http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**",  "/locale", "/api/clientes/listar**").permitAll()
//		.antMatchers("/ver/**").hasAnyRole("USER")
//		.antMatchers("/uploads/**").hasAnyRole("USER")
//		.antMatchers("/form/**").hasAnyRole("ADMIN")
//		.antMatchers("/eliminar/**").hasAnyRole("ADMIN")
//		.antMatchers("/factura/**").hasAnyRole("ADMIN")
		.anyRequest().authenticated()
		.and()
			.formLogin()
			.successHandler(successHandler)
			.loginPage("/login")
			.permitAll()
		.and()
		.addFilter(new JWTAuthenticationFilter(this.authenticationManager(), jwtService))
		.addFilter(new JWTAuthorizationFilter(this.authenticationManager(), jwtService))
		.logout().permitAll()
		.and()
		.exceptionHandling().accessDeniedPage("/error_403")
		.and()
		.csrf().disable()
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		
	}
	
	
	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception{
			
//		builder.jdbcAuthentication()
//		.dataSource(dataSource)
//		.passwordEncoder(passwordEncoder)
//		.usersByUsernameQuery("select username, password,enabled from users where username=?")
//		.authoritiesByUsernameQuery("select u.username, a.authority from authorities a inner join users u on (a.user_id=u.id) where u.username=?");
		
		builder.userDetailsService(userDetailsService)
		.passwordEncoder(passwordEncoder);
		
		
		}
	
	
	
}
