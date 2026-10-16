package dev.passkeyforge;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;
@SpringBootApplication @EnableScheduling
public class PasskeyForge {
 public static void main(String[] args) { SpringApplication.run(PasskeyForge.class,args); }
}
