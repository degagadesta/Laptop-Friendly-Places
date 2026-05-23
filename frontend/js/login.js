import { auth, redirectIfAuthenticated } from './auth.js';

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log("Login page loaded");

    // Check if already logged in
    redirectIfAuthenticated();

    // Get forms
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");

    function clearErrors() {
        document.querySelectorAll(".error").forEach(e => e.innerText = "");
        document.querySelectorAll(".msg").forEach(e => e.style.display = "none");
    }

    // Switch buttons
    document.getElementById("showSignup").onclick = () => {
        console.log("Switching to signup");
        loginForm.classList.remove("active");
        signupForm.classList.add("active");
        clearErrors();
    };

    document.getElementById("showLogin").onclick = () => {
        console.log("Switching to login");
        signupForm.classList.remove("active");
        loginForm.classList.add("active");
        clearErrors();
    };

    // Sign Up Handler
    const signUp = async (name, email, password) => {
        const submitText = signupForm.querySelector(".btn-text");
        const spinner = signupForm.querySelector(".spinner");
        const msg = document.getElementById("message");

        submitText.style.display = "none";
        spinner.style.display = "block";

        try {
            const data = await auth.register(name, email, password);

            msg.style.display = "block";
            msg.style.color = "#4CAF50";
            msg.style.background = "rgba(76, 175, 80, 0.1)";
            msg.style.border = "1px solid #4CAF50";
            msg.innerText = data.message || "Account created! Please check your email to verify your account.";

            console.log("User created:", data.user);

        } catch (error) {
            console.error("Signup error:", error);
            msg.style.display = "block";
            msg.style.color = "#ff4757";
            msg.style.background = "rgba(255, 71, 87, 0.1)";
            msg.style.border = "1px solid #ff4757";
            msg.innerText = error.message || "Error creating account. Please try again.";
        } finally {
            submitText.style.display = "block";
            spinner.style.display = "none";
        }
    }

    // Login Handler
    const logIn = async (email, password) => {
        const submitText = loginForm.querySelector(".btn-text");
        const spinner = loginForm.querySelector(".spinner");
        const msg = document.getElementById("loginMsg");

        if (!submitText || !spinner) {
            console.error("Required DOM elements (submitText or spinner) were not found.");
            return;
        }

        submitText.style.display = "none";
        spinner.style.display = "block";

        try {
            const data = await auth.login(email, password);

            console.log("User logged in successfully:", data.user);

            // Redirect to home page
            window.location.replace("home.html");

        } catch (error) {
            console.error("Login error:", error);
            msg.style.display = "block";
            msg.style.color = "#ff4757";
            msg.style.background = "rgba(255, 71, 87, 0.1)";
            msg.style.border = "1px solid #ff4757";
            msg.innerText = error.message || "Login failed. Please try again.";
        } finally {
            submitText.style.display = "block";
            spinner.style.display = "none";
        }
    }

    /* ================= SIGN UP ================= */
    signupForm.addEventListener("submit", function (e) {
        e.preventDefault();
        clearErrors();

        const name = document.getElementById("signupName").value.trim();
        const email = document.getElementById("signupEmail").value.trim();
        const password = document.getElementById("signupPassword").value;
        const confirm = document.getElementById("signupConfirm").value;

        if (!name || !email || !password || !confirm) {
            alert("All fields are required!");
            return;
        }

        if (password.length < 8) {
            alert("Password must be at least 8 characters");
            return;
        }

        if (password !== confirm) {
            alert("Passwords do not match");
            return;
        }

        signUp(name, email, password);
    });

    /* ================= LOGIN ================= */
    loginForm.addEventListener("submit", function (e) {
        e.preventDefault();
        clearErrors();

        const email = document.getElementById("loginEmail").value.trim();
        const password = document.getElementById("loginPassword").value;

        if (!email || !password) {
            alert("Please enter email and password");
            return;
        }

        logIn(email, password);
    });

    // Password Eye Toggle
    document.querySelectorAll(".toggle").forEach(icon => {
        icon.addEventListener("click", () => {
            const input = document.getElementById(icon.dataset.target);

            if (input.type === "password") {
                input.type = "text";
                icon.classList.remove("fa-eye");
                icon.classList.add("fa-eye-slash");
            } else {
                input.type = "password";
                icon.classList.remove("fa-eye-slash");
                icon.classList.add("fa-eye");
            }
        });
    });
});
