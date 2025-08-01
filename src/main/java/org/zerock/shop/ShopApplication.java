package org.zerock.shop;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//@RestController  // @Controller + @ResponseBoby를 합쳐 놓음.
@SpringBootApplication
public class ShopApplication {

    public static void main(String[] args) {
        SpringApplication.run(ShopApplication.class, args);
    }

//    @GetMapping(value = "/")
//    public String HelloWorld(){
//        return "Hello World";
//    }

}
