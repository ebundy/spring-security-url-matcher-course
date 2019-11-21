package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Profile("!monolithConfiguration")
@Configuration
@Order(10)
@EnableWebSecurity(debug = false)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("admin").password(passwordEncoder.encode("123")).roles("USER","ADMIN").and()
        .withUser("foouser").password(passwordEncoder .encode("123")).roles("USER");
  }


  @Profile("!monolithConfiguration")
  @Configuration
  @Order(9)
  public static class WebSecurityConfigH2 extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception { // @formatter:off
      http.csrf().disable()
          .antMatcher("/h2-console/**")
          .authorizeRequests()
          .anyRequest().hasRole("ADMIN").
              and().headers().frameOptions().disable()
          .and()
          .formLogin().permitAll();
    }
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.antMatcher("/**")
        .authorizeRequests().antMatchers("/public.html", "/login").permitAll()

        .and()
        .formLogin().permitAll()

        .and()
        .authorizeRequests()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().hasRole("USER");
  }

}
