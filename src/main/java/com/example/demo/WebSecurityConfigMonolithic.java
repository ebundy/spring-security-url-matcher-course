package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Profile("monolithConfiguration")
@Configuration
@EnableWebSecurity(debug = false)
public class WebSecurityConfigMonolithic extends WebSecurityConfigurerAdapter {

  @Autowired
  private BCryptPasswordEncoder passwordEncoder;

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.inMemoryAuthentication()
        .withUser("admin").password(passwordEncoder.encode("123")).roles("USER","ADMIN").and()
        .withUser("foouser").password(passwordEncoder.encode("123")).roles("USER");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception { // @formatter:off
    http.csrf().disable()
    .antMatcher("/**")
        .authorizeRequests().antMatchers("/public.html", "/login")
        .permitAll()

        .and()
        .formLogin().permitAll()

        .and()
        .authorizeRequests()
        .antMatchers("/admin/**","/h2-console/**").hasRole("ADMIN")
        .anyRequest().hasRole("USER");
  }
}
