package org.dpppt.backend.sdk.ws.controller;


import org.dpppt.backend.sdk.ws.security.FrontalResponseLogin;
import org.dpppt.backend.sdk.ws.security.FrontalSecurityService;
import org.dpppt.backend.sdk.ws.security.FrontalUserLogin;
import org.dpppt.backend.sdk.ws.security.OTPKeyGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
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
	
	@Autowired
	FrontalSecurityService frontalService;
	

	@GetMapping("login")
	public String sendToLogin(Model model) {
		
		model.addAttribute("userLogin", new FrontalUserLogin());
		return "login";
	}
	
	@PostMapping("login")
	public ModelAndView doLogin(@ModelAttribute FrontalUserLogin userLogin, Model model){

		FrontalResponseLogin response = frontalService.validateUser(userLogin);
		
		if(response.getToken()==null || response.getToken().isEmpty()) {
			return new ModelAndView("login")
					.addObject("response", response)
					.addObject("userLogin", new FrontalUserLogin());
		}
		return new ModelAndView("landing").addObject("response", response);
		
	}
	
	
	@PostMapping("generate-code")
	public ResponseEntity<FrontalResponseLogin> sendToGeneratedCode() {
		
		FrontalResponseLogin response = new FrontalResponseLogin();
		try {
			response.setToken(frontalService.generateJWTToken());
			OTPKeyGenerator otpKeyGenerator = new OTPKeyGenerator(seedKey);
			String otp = otpKeyGenerator.getOneTimePassword("TOTP", 6, true);
			response.setOtp(otp);
		} catch (Exception e) {
			e.printStackTrace();
			response.setError("Error generating code");
		} 

		return ResponseEntity.ok().body(response);
	}

}
