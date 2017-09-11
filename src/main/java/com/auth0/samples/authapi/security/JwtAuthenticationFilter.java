package com.auth0.samples.authapi.security;

import com.auth0.samples.authapi.user.ApplicationUser;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.JSONPObject;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static com.auth0.samples.authapi.security.SecurityConstants.*;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		String header = request.getHeader(HEADER_STRING);
		String decodedHeader = new String(Base64Utils.decodeFromString(StringUtils.delete(header, BASIC_PREFIX)));
		String[] credentials = decodedHeader.split(":");
		String username = credentials[0];
		String password = credentials[1];
		ApplicationUser user = new ApplicationUser(username, password);

		return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                user.getUsername(), user.getPassword(), new ArrayList<>()
        ));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
											FilterChain chain, Authentication auth) throws IOException, ServletException {
		String token = Jwts.builder()
							.setSubject(((User) auth.getPrincipal()).getUsername())
							.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
							.signWith(SignatureAlgorithm.HS512, SECRET)
							.compact();
		Map<String, String> tokenMap = new HashMap<>();
		ObjectMapper mapper = new ObjectMapper();

		tokenMap.put("token", token);
		response.getWriter().write(mapper.writeValueAsString(tokenMap));
	}

}
