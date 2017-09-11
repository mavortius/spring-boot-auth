package com.auth0.samples.authapi.user;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private final ApplicationUserRepository repository;

	public UserDetailsServiceImpl(ApplicationUserRepository repository) {
		this.repository = repository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		ApplicationUser applicationUser = repository.findByUsername(username);

		if(applicationUser == null) {
			throw new UsernameNotFoundException(username);
		} else {
			return new User(applicationUser.getUsername(), applicationUser.getPassword(), Collections.emptyList());
		}
	}
}
