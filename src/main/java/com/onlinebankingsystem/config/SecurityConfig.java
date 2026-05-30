package com.onlinebankingsystem.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value; // Added this import
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration; // Added this import
import org.springframework.web.cors.CorsConfigurationSource; // Added this import
import org.springframework.web.cors.UrlBasedCorsConfigurationSource; // Added this import

import com.onlinebankingsystem.filter.JwtAuthFilter;
import com.onlinebankingsystem.utility.Constants.UserRole;

import java.util.Arrays; // Added this import
import java.util.List;   // Added this import

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	
	@Autowired
	private JwtAuthFilter authFilter;

	// 1. Pull the URL value from application.properties professionally
	@Value("${app.cors.allowed-origins:http://localhost:3000}")
	private String allowedOrigins;

	@Bean
	// authentication
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailsService();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.csrf(csrf -> csrf.disable())
		        // 2. FIXED: Link your professional CORS config source here instead of disabling it
		        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
		    
				.authorizeHttpRequests(
						auth -> auth.requestMatchers("/api/user/login", "/api/user/admin/register").permitAll()
						
                        // Allow browser CORS preflight requests
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						// this APIs are only accessible by ADMIN
						.requestMatchers("/api/bank/register","/api/bank/fetch/all", "/api/bank/fetch/user",
								"/api/bank/account/fetch/all", "/api/bank/transaction/all")
						.hasAuthority(UserRole.ROLE_ADMIN.value())
						
						// this APIs are only accessible by BANK
						.requestMatchers("/api/bank/account/add","/api/bank/account/fetch/bankwise","/api/bank/account/fetch/id"
								,"/api/bank/account/search","/api/bank/transaction/deposit","/api/bank/transaction/withdraw",
								"/api/bank/transaction/customer/fetch", "/api/bank/transaction/customer/fetch/timerange",
								"/api/bank/transaction/all/customer/fetch/timerange", "/api/bank/transaction/all/customer/fetch",
								"/api/user/bank/customer/search")
						.hasAuthority(UserRole.ROLE_BANK.value())
						
						// this APIs are only accessible by CUSTOMER
						.requestMatchers("/api/bank/transaction/account/transfer",
								"/api/bank/transaction/history/timerange")
						.hasAuthority(UserRole.ROLE_CUSTOMER.value())
						
						// this APIs are only accessible by BANK & CUSTOMER
						.requestMatchers("/api/bank/account/fetch/user", "/api/bank/transaction/history")
						.hasAnyAuthority(UserRole.ROLE_BANK.value(), UserRole.ROLE_CUSTOMER.value(), UserRole.ROLE_ADMIN.value())
						
						// this APIs are only accessible by BANK & ADMIN
						.requestMatchers("/api/user/register", "/api/bank/account/search/all")
						.hasAnyAuthority(UserRole.ROLE_BANK.value(), UserRole.ROLE_ADMIN.value())
						
						// this APIs are only accessible by BANK, ADMIN & CUSTOMER
						.requestMatchers("/api/bank/fetch/id", "/api/bank/transaction/statement/download")
						.hasAnyAuthority(UserRole.ROLE_BANK.value(), UserRole.ROLE_ADMIN.value(), UserRole.ROLE_CUSTOMER.value())
						
						.anyRequest()
						.authenticated())
		        
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		http.addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();

	}

	// 3. Added this professional CORS rules bean configuration at the bottom
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		
		configuration.setAllowedOrigins(List.of(allowedOrigins)); 
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
		configuration.setAllowCredentials(true); 

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration); 
		return source;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		return authenticationProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

}
