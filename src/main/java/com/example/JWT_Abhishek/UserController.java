package com.example.JWT_Abhishek;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class UserController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTUtil jwtUtil;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/login")
    public String loginUser(User user, RedirectAttributes redirectAttributes) {
        User existingUser = userRepository.findByEmail(user.getEmail());
        if (existingUser != null && user.getPassword().equals(existingUser.getPassword())) {
            String token = jwtUtil.generateToken(existingUser.getEmail());
            redirectAttributes.addAttribute("token", token);
            if (existingUser.getType().equals("user")) {
                return "redirect:/user-detail";
            } else if (existingUser.getType().equals("admin")) {
                return "redirect:/admin-detail";
            }
        }
        return "redirect:/login?error";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }

    @PostMapping("/signup")
    public String signupUser(User user, RedirectAttributes redirectAttributes) {
        if (userRepository.findByEmail(user.getEmail()) == null) {
            userRepository.save(user);
            String token = jwtUtil.generateToken(user.getEmail());
            redirectAttributes.addAttribute("token", token);
            return "redirect:/user-detail";
        }
        return "redirect:/signup?error";
    }

    @GetMapping("/user-detail")
    public String userDetail(Model model, HttpServletRequest request) {
        String token = request.getParameter("token");
        if (token != null && jwtUtil.validateToken(token)) {
            return "user-detail";
        } else {
            return "redirect:/login";
        }
    }

    @GetMapping("/admin-detail")
    public String adminDetail(Model model, HttpServletRequest request) {
        String token = request.getParameter("token");
        if (token != null && jwtUtil.validateToken(token)) {
            return "admin-detail";
        } else {
            return "redirect:/login";
        }
    }
}
