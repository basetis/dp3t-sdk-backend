package org.dpppt.backend.sdk.ws.controller;


import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequestMapping("/admin")
public class FrontalController {
	
	
	//@CrossOrigin(origins = "http://localhost:9000")
	@GetMapping("index")
	public String sendToIndex(Model model) {
		return "index";
	}

}
