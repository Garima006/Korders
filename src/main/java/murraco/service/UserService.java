package murraco.service;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import murraco.dto.UserPasswordResetDTO;
import murraco.exception.CustomException;
import murraco.model.User;
import murraco.model.UserStatus;
import murraco.repository.UserRepository;
import murraco.security.JwtTokenProvider;

@Service
public class UserService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @Autowired
  private JwtTokenProvider jwtTokenProvider;

  @Autowired
  private AuthenticationManager authenticationManager;

  public String signin(String username, String password) {
    try {
      authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
      return jwtTokenProvider.createToken(username, userRepository.findByUsername(username).getRoles());
    } catch (AuthenticationException e) {
      throw new CustomException("Invalid username/password", HttpStatus.UNPROCESSABLE_ENTITY);
    }
  }

  public String signup(User user) {
    if (!userRepository.existsByUsername(user.getUsername())) {
      user.setPassword(passwordEncoder.encode(user.getPassword()));
      user.setStatus(UserStatus.VALID_USER.toString());
      userRepository.save(user);
      return jwtTokenProvider.createToken(user.getUsername(), user.getRoles());
    } else {
      throw new CustomException("Username is already in use", HttpStatus.UNPROCESSABLE_ENTITY);
    }
  }

  public void delete(String username) {
    userRepository.deleteByUsername(username);
  }

  public User search(String username) {
    User user = userRepository.findByUsername(username);
    if (user == null) {
      throw new CustomException("The user doesn't exist", HttpStatus.NOT_FOUND);
    }
    return user;
  }

  public User whoami(HttpServletRequest req) {
    return userRepository.findByUsername(jwtTokenProvider.getUsername(jwtTokenProvider.resolveToken(req)));
  }

  public String refresh(String username) {
    return jwtTokenProvider.createToken(username, userRepository.findByUsername(username).getRoles());
  }
  
  public String forgetPassword(String email) {
	  User user = userRepository.findByEmail(email);
	  
	  if(user != null) {
		  if(user.getStatus().equals(UserStatus.PASSWORD_REQUESTED.toString())) {
			  return "Password reset request is already in progress";
		  } else {
			  user.setStatus(UserStatus.PASSWORD_REQUESTED.toString());
			  this.userRepository.save(user);
			  return "Password reset request has been sent successfully";
		  }
	  }
	  
	  return null;
  }
  
  public void changePassword(UserPasswordResetDTO dto) {
	  
	  User user = userRepository.findByEmail(dto.getEmail());
	  
	  if(user != null && user.getStatus().equals(UserStatus.PASSWORD_REQUESTED.toString())) {
		  user.setPassword(passwordEncoder.encode(dto.getPassword()));
		  this.userRepository.save(user);
	  }	  
  }
}