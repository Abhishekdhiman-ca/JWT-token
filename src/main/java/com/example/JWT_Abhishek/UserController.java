package com.example.JWT_Abhishek;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class UserController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JWTUtil jwtUtil;

    @GetMapping("/")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login")
    public String loginUser(@RequestParam String email, @RequestParam String password, HttpSession session, Model model) {
        if (email.isEmpty() || password.isEmpty()) {
            model.addAttribute("error", "Please provide email address and password");
            return "login";
        }

        if (!isValidEmailAddress(email)) {
            model.addAttribute("error", "Please provide a valid email address");
            return "login";
        }

        User existingUser = userRepository.findByEmail(email);
        if (existingUser != null && existingUser.getPassword().equals(password)) {
            String token = jwtUtil.generateToken(existingUser.getEmail());
            session.setAttribute("user", existingUser);
            session.setAttribute("token", token);

            if ("user".equals(existingUser.getType())) {
                return "redirect:/user-detail";
            } else if ("admin".equals(existingUser.getType())) {
                return "redirect:/admin-detail";
            }
        } else {
            model.addAttribute("error", "Invalid email or password");
            return "login";
        }

        return "redirect:/login?error";
    }

    @GetMapping("/signup")
    public String signupPage() {
        return "signup";
    }

    @PostMapping("/signup")
    public String signupUser(@RequestParam String name, @RequestParam String email, @RequestParam String password, HttpSession session, RedirectAttributes redirectAttributes) {
        if (name.isEmpty() || email.isEmpty() || password.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "Please fill out all fields");
            return "redirect:/signup";
        }

        if (!isValidEmailAddress(email)) {
            redirectAttributes.addFlashAttribute("error", "Please provide a valid email address");
            return "redirect:/signup";
        }

        if (userRepository.findByEmail(email) == null) {
            User user = new User();
            user.setName(name);
            user.setEmail(email);
            user.setPassword(password);
            user.setType("user"); // Default type, can be modified as needed
            userRepository.save(user);

            String token = jwtUtil.generateToken(user.getEmail());
            session.setAttribute("user", user);
            session.setAttribute("token", token);

            return "redirect:/user-detail";
        } else {
            redirectAttributes.addFlashAttribute("error", "Email is already registered");
            return "redirect:/signup";
        }
    }

    @GetMapping("/user-detail")
    public String userDetail(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        String token = (String) session.getAttribute("token");

        if (user != null && jwtUtil.validateToken(token)) {
            model.addAttribute("user", user);
            return "user-detail";
        } else {
            return "redirect:/";
        }
    }

    @GetMapping("/admin-detail")
    public String adminDetail(HttpSession session, Model model) {
        User user = (User) session.getAttribute("user");
        String token = (String) session.getAttribute("token");

        if (user != null && jwtUtil.validateToken(token)) {
            model.addAttribute("user", user);
            return "admin-detail";
        } else {
            return "redirect:/";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/";
    }

    private boolean isValidEmailAddress(String email) {
        String ePattern = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))$";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(ePattern);
        java.util.regex.Matcher m = p.matcher(email);
        return m.matches();
    }
}
