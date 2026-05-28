import { auth, redirectIfAuthenticated } from './auth.js';

document.addEventListener('DOMContentLoaded', () => {
    redirectIfAuthenticated();

    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");

    function clearErrors() {
        document.querySelectorAll(".error").forEach(e => e.innerText = "");
        document.querySelectorAll(".msg").forEach(e => e.style.display = "none");
    }

    document.getElementById("showSignup").onclick = () => {
        loginForm.classList.remove("active");
        signupForm.classList.add("active");
        clearErrors();
    };

    document.getElementById("showLogin").onclick = () => {
        signupForm.classList.remove("active");
        loginForm.classList.add("active");
        clearErrors();
    };

    // Sign Up
    signupForm.addEventListener("submit", async function (e) {
        e.preventDefault();
        clearErrors();

        const name = document.getElementById("signupName").value.trim();
        const email = document.getElementById("signupEmail").value.trim();
        const password = document.getElementById("signupPassword").value;
        const confirm = document.getElementById("signupConfirm").value;
        const msg = document.getElementById("message");

        if (!name || !email || !password || !confirm) { alert("All fields are required!"); return; }
        if (password.length < 8) { alert("Password must be at least 8 characters"); return; }
        if (password !== confirm) { alert("Passwords do not match"); return; }

        const submitText = signupForm.querySelector(".btn-text");
        const spinner = signupForm.querySelector(".spinner");
        submitText.style.display = "none";
        spinner.style.display = "block";

        try {
            const data = await auth.register(name, email, password);
            msg.style.display = "block";
            msg.style.color = "#4CAF50";
            msg.style.background = "rgba(76,175,80,0.1)";
            msg.style.border = "1px solid #4CAF50";
            msg.innerText = data.message || "Account created! Please check your email to verify your account.";
        } catch (error) {
            msg.style.display = "block";
            msg.style.color = "#ff4757";
            msg.style.background = "rgba(255,71,87,0.1)";
            msg.style.border = "1px solid #ff4757";
            msg.innerText = error.message || "Error creating account. Please try again.";
        } finally {
            submitText.style.display = "block";
            spinner.style.display = "none";
        }
    });

    // Login
    loginForm.addEventListener("submit", async function (e) {
        e.preventDefault();
        clearErrors();

        const email = document.getElementById("loginEmail").value.trim();
        const password = document.getElementById("loginPassword").value;
        const msg = document.getElementById("loginMsg");

        if (!email || !password) { alert("Please enter email and password"); return; }

        const submitText = loginForm.querySelector(".btn-text");
        const spinner = loginForm.querySelector(".spinner");
        submitText.style.display = "none";
        spinner.style.display = "block";

        try {
            await auth.login(email, password);
            window.location.replace("home.html");
        } catch (error) {
            msg.style.display = "block";
            msg.style.color = "#ff4757";
            msg.style.background = "rgba(255,71,87,0.1)";
            msg.style.border = "1px solid #ff4757";
            msg.innerText = error.message || "Login failed. Please try again.";
        } finally {
            submitText.style.display = "block";
            spinner.style.display = "none";
        }
    });

    // Password toggle
    document.querySelectorAll(".toggle").forEach(icon => {
        icon.addEventListener("click", () => {
            const input = document.getElementById(icon.dataset.target);
            if (input.type === "password") {
                input.type = "text";
                icon.classList.replace("fa-eye", "fa-eye-slash");
            } else {
                input.type = "password";
                icon.classList.replace("fa-eye-slash", "fa-eye");
            }
        });
    });
});
