package seyoung.toyproject;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;

@SpringBootApplication
@EnableCaching
public class ToyprojectApplication {

	public static void main(String[] args) {
		SpringApplication.run(ToyprojectApplication.class, args);
	}

}
