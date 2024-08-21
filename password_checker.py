import tkinter as tk
from tkinter import ttk
from ttkthemes import ThemedTk
import random
import string
import re
import hashlib
import math
import logging

# Set up logging
logging.basicConfig(filename='password_checker.log', level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def get_logger(name):
    return logging.getLogger(name)

def generate_password(length=12, use_uppercase=True, use_numbers=True, use_symbols=True):
    logger = get_logger(f"{__name__}.generate_password")
    logger.debug(f"Generating password with length={length}, uppercase={use_uppercase}, numbers={use_numbers}, symbols={use_symbols}")

    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase if use_uppercase else ''
    numbers = string.digits if use_numbers else ''
    symbols = string.punctuation if use_symbols else ''
    
    all_characters = lowercase + uppercase + numbers + symbols
    
    if len(all_characters) == 0:
        logger.error("No character set selected for password generation")
        return "Error: No character set selected"
    
    password = ''.join(random.choice(all_characters) for _ in range(length))
    logger.info(f"Password generated successfully with length {length}")
    return password

def check_password_strength(password):
    logger = get_logger(f"{__name__}.check_password_strength")
    logger.debug(f"Checking strength for password: {password[:2]}{'*' * (len(password) - 4)}{password[-2:]}")
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
        feedback.append("Good length")
    else:
        feedback.append("Password should be at least 12 characters long")

    if re.search(r"[A-Z]", password):
        score += 1
        feedback.append("Contains uppercase letters")
    else:
        feedback.append("Should contain uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
        feedback.append("Contains lowercase letters")
    else:
        feedback.append("Should contain lowercase letters")

    if re.search(r"\d", password):
        score += 1
        feedback.append("Contains numbers")
    else:
        feedback.append("Should contain numbers")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
        feedback.append("Contains symbols")
    else:
        feedback.append("Should contain symbols")

    strength = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"][min(score, 4)]
    logger.info(f"Password strength check completed. Result: {strength}")
    return strength, feedback

def apply_salt_pepper(password, salt="qwer", pepper="zxcv"):
    logger = get_logger(f"{__name__}.apply_salt_pepper")
    logger.debug("Applying salt and pepper to password")
    return salt + password + pepper

def hash_password(password):
    logger = get_logger(f"{__name__}.hash_password")
    logger.debug("Hashing password")
    return hashlib.sha256(password.encode()).hexdigest()

def estimate_crack_time(password):
    logger = get_logger(f"{__name__}.estimate_crack_time")
    logger.debug("Estimating crack time for password")
    # Estimate entropy
    char_set_size = 0
    if re.search(r"[a-z]", password):
        char_set_size += 26
    if re.search(r"[A-Z]", password):
        char_set_size += 26
    if re.search(r"\d", password):
        char_set_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        char_set_size += 32
    
    entropy = math.log2(char_set_size ** len(password))
    
    # Estimate time based on entropy
    guesses_per_second = 1e10  # Assume 10 billion guesses per second
    seconds = 2 ** entropy / guesses_per_second
    
    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    elif seconds < 3153600000:
        return f"{seconds/31536000:.1f} years"
    else:
        return "Centuries"

class EnhancedPasswordApp(ThemedTk):
    def __init__(self):
        super().__init__(theme="breeze")  # You can try other themes like "equilux", "breeze", etc.

        self.logger = get_logger(f"{__name__}.EnhancedPasswordApp")
        self.logger.info("Initializing EnhancedPasswordApp")

        self.title("Enhanced Secure Password Tool")
        self.geometry("900x700")
        self.configure(bg="#f0f0f0")

        self.create_widgets()

    def create_widgets(self):
        self.logger.debug("Creating widgets for EnhancedPasswordApp")
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # User Password Section
        user_frame = ttk.LabelFrame(main_frame, text="Check Your Password", padding="10")
        user_frame.pack(fill=tk.X, pady=10)

        ttk.Label(user_frame, text="Enter Your Password:").pack(side=tk.LEFT, padx=5)
        self.user_password = ttk.Entry(user_frame, show="•", width=30)
        self.user_password.pack(side=tk.LEFT, padx=5)

        # Salt and Pepper Section
        salt_pepper_frame = ttk.Frame(user_frame)
        salt_pepper_frame.pack(side=tk.LEFT, padx=5)

        ttk.Label(salt_pepper_frame, text="Salt:").grid(row=0, column=0, sticky="e")
        self.salt_entry = ttk.Entry(salt_pepper_frame, width=15)
        self.salt_entry.grid(row=0, column=1, padx=2, pady=2)

        ttk.Label(salt_pepper_frame, text="Pepper:").grid(row=1, column=0, sticky="e")
        self.pepper_entry = ttk.Entry(salt_pepper_frame, width=15)
        self.pepper_entry.grid(row=1, column=1, padx=2, pady=2)

        ttk.Button(user_frame, text="Check Strength", command=self.check_user_password).pack(side=tk.LEFT, padx=10)

        # Generated Password Section
        gen_frame = ttk.LabelFrame(main_frame, text="Generate Password", padding="10")
        gen_frame.pack(fill=tk.X, pady=10)

        self.length_var = tk.IntVar(value=12)
        ttk.Label(gen_frame, text="Length:").pack(side=tk.LEFT)
        self.length_entry = ttk.Entry(gen_frame, textvariable=self.length_var, width=5)
        self.length_entry.pack(side=tk.LEFT, padx=5)
        
        length_scale = ttk.Scale(gen_frame, from_=8, to=50, variable=self.length_var, 
                                 orient="horizontal", length=200, command=self.round_scale_value)
        length_scale.pack(side=tk.LEFT, padx=5)

        options_frame = ttk.Frame(gen_frame)
        options_frame.pack(side=tk.LEFT, padx=20)

        self.uppercase_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(options_frame, text="Uppercase", variable=self.uppercase_var).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Numbers", variable=self.numbers_var).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Symbols", variable=self.symbols_var).pack(anchor="w")

        ttk.Button(gen_frame, text="Generate Password", command=self.generate_and_check).pack(side=tk.LEFT, padx=10)

        # Results Section
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.result_text = tk.Text(results_frame, height=15, width=80, wrap=tk.WORD, font=("TkDefaultFont", 10))
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.configure(yscrollcommand=scrollbar.set)

        # Strength Meter
        self.strength_meter = ttk.Progressbar(main_frame, orient="horizontal", length=300, mode="determinate")
        self.strength_meter.pack(pady=10)

    def check_user_password(self):
        self.logger.info("User initiated password check")
        password = self.user_password.get()
        salt = self.salt_entry.get()
        pepper = self.pepper_entry.get()
        
        try:
            salted_peppered_password = apply_salt_pepper(password, salt, pepper)
            strength, feedback = check_password_strength(salted_peppered_password)
            
            hashed_password = hash_password(salted_peppered_password)
            crack_time = estimate_crack_time(salted_peppered_password)
            
            self.display_results("Your Password", password, strength, feedback, salt, pepper, hashed_password, crack_time)
            self.update_strength_meter(strength)
            self.logger.info("Password check completed successfully")
        except Exception as e:
            self.logger.error(f"Error during password check: {str(e)}", exc_info=True)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"An error occurred: {str(e)}")

    def round_scale_value(self, value):
        rounded_value = round(float(value))
        self.length_var.set(rounded_value)
        self.logger.debug(f"Rounded scale value to {rounded_value}")

    def generate_and_check(self):
        self.logger.info("User initiated password generation and check")
        try:
            length = self.length_var.get()
            if length < 8 or length > 50:
                raise ValueError
        except ValueError as e:
            length = 12  # Default to 12 if invalid input
            self.length_var.set(length)
            self.logger.warning(f"Invalid length input. Defaulting to {length}: {str(e)}")
        try:
            password = generate_password(
                length,
                self.uppercase_var.get(),
                self.numbers_var.get(),
                self.symbols_var.get()
            )
            
            salt = self.salt_entry.get()
            pepper = self.pepper_entry.get()
            
            salted_peppered_password = apply_salt_pepper(password, salt, pepper)
            strength, feedback = check_password_strength(salted_peppered_password)
            
            hashed_password = hash_password(salted_peppered_password)
            crack_time = estimate_crack_time(salted_peppered_password)
            
            self.display_results("Generated Password", password, strength, feedback, salt, pepper, hashed_password, crack_time)
            self.update_strength_meter(strength)
        except Exception as e:
            self.logger.error(f"Error during password generation and check: {str(e)}", exc_info=True)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"An error occurred: {str(e)}")
    
    
    def update_strength_meter(self, strength):
        strength_values = {"Very Weak": 20, "Weak": 40, "Moderate": 60, "Strong": 80, "Very Strong": 100}
        self.strength_meter["value"] = strength_values.get(strength, 0)
        self.logger.debug(f"Updated strength meter to {strength}")

    def display_results(self, password_type, password, strength, feedback, salt, pepper, hashed_password, crack_time):
        self.logger.debug(f"Displaying results for {password_type}")        
        self.result_text.delete(1.0, tk.END)
        
        if password_type == "Your Password":
            self.result_text.insert(tk.END, f"{password_type}: [HIDDEN]\n", "bold")
            self.logger.info(f"Your password is Logged here: $$$$$$$$ ---- {password} ---- $$$$$$$$")
        else:
            self.result_text.insert(tk.END, f"{password_type}: {password}\n", "bold")
        
        self.result_text.insert(tk.END, f"Salt: {salt}\n")
        self.result_text.insert(tk.END, f"Pepper: {pepper}\n")
        
        if password_type == "Your Password":
            self.result_text.insert(tk.END, f"Salted & Peppered: [HIDDEN]\n")
        else:
            self.result_text.insert(tk.END, f"Salted & Peppered: {salt + password + pepper}\n")
        
        self.result_text.insert(tk.END, f"Strength: {strength}\n", "bold")
        self.result_text.insert(tk.END, "Feedback:\n", "bold")
        for item in feedback:
            self.result_text.insert(tk.END, f"• {item}\n")
        self.result_text.insert(tk.END, f"\nHashed Password:\n{hashed_password}\n", "bold")
        self.result_text.insert(tk.END, f"\nEstimated time to crack: {crack_time}\n", "bold")

        self.result_text.tag_configure("bold", font=("TkDefaultFont", 10, "bold"))

if __name__ == "__main__":
    main_logger = get_logger(__name__)
    main_logger.info("Starting EnhancedPasswordApp")
    app = EnhancedPasswordApp()
    app.mainloop()
    main_logger.info("EnhancedPasswordApp closed")