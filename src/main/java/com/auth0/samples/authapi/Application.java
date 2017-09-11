package com.auth0.samples.authapi;

import com.auth0.samples.authapi.task.Task;
import com.auth0.samples.authapi.task.TaskRepository;
import com.auth0.samples.authapi.user.ApplicationUser;
import com.auth0.samples.authapi.user.ApplicationUserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class Application implements CommandLineRunner {
	private static final Logger log = LoggerFactory.getLogger(Application.class);

	@Autowired
	private ApplicationUserRepository userRepository;

	@Autowired
	private TaskRepository taskRepository;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}


	@Override
	public void run(String... args) throws Exception {
		PasswordEncoder passwordEncoder = passwordEncoder();

		log.info("Inserting user data...");
		userRepository.save(new ApplicationUser("admin", passwordEncoder.encode("admin")));
		userRepository.save(new ApplicationUser("user", passwordEncoder.encode("user")));

		log.info("Created users:");
		userRepository.findAll().forEach(u -> log.info(u.getUsername()));

		log.info("Inserting tasks data...");
		taskRepository.save(new Task("todos"));
		taskRepository.save(new Task("nothing todo"));
		taskRepository.save(new Task("to rest"));

	}
}
