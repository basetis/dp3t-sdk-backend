package org.dpppt.backend.sdk.ws.controller;


import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.dpppt.backend.sdk.ws.security.OTPKeyGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/admin")
public class FrontalController {

	@Value("${ws.app.otp.seedKey}")
	private String seedKey;

	@GetMapping("login")
	public String sendToLogin(Model model) {
		model.addAttribute("userLogin", new UserLogin());
		return "login";
	}
	
	@PostMapping("index")
	public ModelAndView sendToIndex(@ModelAttribute UserLogin userLogin, Model model) {
		if(userLogin.getUsername().isEmpty()) {
			return new ModelAndView("login").addObject("userLogin", new UserLogin()).addObject("error", "Empty Username");
		}
		if(userLogin.getPassword().isEmpty()) {
			return new ModelAndView("login").addObject("userLogin", new UserLogin()).addObject("error", "Empty Password");
		}
		if(!userLogin.getUsername().equals("admin")) {
			return new ModelAndView("login").addObject("userLogin", new UserLogin()).addObject("error", "Invalid login");
		}
		if(!userLogin.getPassword().equals("admin")) {
			return new ModelAndView("login").addObject("userLogin", new UserLogin()).addObject("error", "Invalid login");
		}
		
		model.addAttribute("userLogin", userLogin);
		return new ModelAndView("index");
	}
	
	@GetMapping("generate-code")
	public String sendToGeneratedCode(Model model) {

		OTPKeyGenerator otpKeyGenerator = new OTPKeyGenerator(seedKey);
		String otp = "Error generating code";
		try {
			otp = otpKeyGenerator.getOneTimePassword("TOTP", 6, true);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		model.addAttribute("code", otp);
		return "generated-code";
	}

}
