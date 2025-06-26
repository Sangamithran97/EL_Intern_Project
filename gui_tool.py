import tkinter as tk
from tkinter import ttk, messagebox
from zxcvbn import zxcvbn
import itertools

# ---------- Wordlist Generator Functions ----------

def leetspeak(word):
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '$'}
    return ''.join(leet_map.get(c, c) for c in word)

def generate_variations(hints):
    combos = set()
    for word in hints:
        combos.add(word)
        combos.add(word.capitalize())
        combos.add(word + "123")
        combos.add("123" + word)
        combos.add(word + "2024")
        combos.add(leetspeak(word))
        combos.add(leetspeak(word) + "123")

    for pair in itertools.permutations(hints, 2):
        combos.add(''.join(pair))
        combos.add(pair[0] + "_" + pair[1])

    return combos

def export_wordlist(words):
    try:
        with open("custom_wordlist.txt", 'w') as f:
            for word in sorted(words):
                f.write(word + "\n")
        messagebox.showinfo("Success", "✅ Wordlist saved to custom_wordlist.txt")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---------- Password Analyzer Function ----------

def analyze_password_gui():
    password = entry_pwd.get()
    if not password:
        messagebox.showwarning("Input Needed", "Please enter a password")
        return

    # Try loading custom wordlist if available
    try:
        with open("custom_wordlist.txt", "r") as f:
            user_words = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        user_words = []

    result = zxcvbn(password, user_inputs=user_words)

    score = result['score']
    time_offline_fast = result['crack_times_display']['offline_fast_hashing_1e10_per_second']
    time_offline_slow = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    
    feedback = result['feedback']
    # Load suggestions from zxcvbn or use default
    suggestions = feedback.get('suggestions') or []

# Load custom wordlist if available
    try:
        with open("custom_wordlist.txt", "r") as f:
            user_words = [line.strip().lower() for line in f.readlines()]
    except FileNotFoundError:
        user_words = []

# Check if any personal word is used in the password
    used_personal_word = any(word in password.lower() for word in user_words)

    if used_personal_word:
        suggestions.append("⚠️ Your password includes personal words (e.g., your name, pet, etc.). These are easy to guess. Avoid using such terms.")

# Fallback suggestion if no suggestions exist
    if not suggestions:
        suggestions = ["No suggestions — this password is strong."]

    # Custom warning logic based on score
    if feedback.get('warning'):
        warning = feedback['warning']
    else:
        if score <= 1:
            warning = "⚠️ This password is very weak. Avoid common words or simple patterns."
        elif score == 2:
            warning = "⚠️ This password is weak. Consider adding more complexity."
        else:
            warning = "✅ No major issues detected."


    output = (
        f"Score (0-4): {score}\n"
        f"🖥 Fast Cracker (10B guesses/sec): {time_offline_fast}\n"
        f"🐢 Slow Cracker (10K guesses/sec): {time_offline_slow}\n"
        f"Suggestions: {', '.join(suggestions)}\n"
        f"Warning: {warning}"
    )
    txt_result.delete(1.0, tk.END)
    txt_result.insert(tk.END, output)



# ---------- Wordlist Generator GUI Function ----------

def generate_wordlist_gui():
    hints = [
        entry_name.get().lower(),
        entry_pet.get().lower(),
        entry_year.get(),
        entry_number.get(),
        entry_custom.get().lower()
    ]
    if not all(hints):
        messagebox.showwarning("Input Needed", "Please fill all fields")
        return
    wordlist = generate_variations(hints)
    export_wordlist(wordlist)

# ---------- Main GUI Setup ----------

root = tk.Tk()
root.title("🔐 Password Tool")
root.geometry("500x400")

notebook = ttk.Notebook(root)
tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
notebook.add(tab1, text="Password Analyzer")
notebook.add(tab2, text="Wordlist Generator")
notebook.pack(expand=True, fill="both")

# ---------- Tab 1: Password Analyzer ----------

tk.Label(tab1, text="Enter Password to Analyze:", font=('Arial', 12)).pack(pady=10)
entry_pwd = tk.Entry(tab1, show="*", font=('Arial', 12), width=40)
entry_pwd.pack()

tk.Button(tab1, text="Analyze", font=('Arial', 11), command=analyze_password_gui).pack(pady=10)

txt_result = tk.Text(tab1, height=10, width=60, font=('Consolas', 10))
txt_result.pack(pady=10)

# ---------- Tab 2: Wordlist Generator ----------

frame_inputs = ttk.Frame(tab2)
frame_inputs.pack(pady=10)

labels = ["Name", "Pet Name", "Birth Year", "Favorite Number", "Custom Word"]
entries = []

for i, label in enumerate(labels):
    tk.Label(frame_inputs, text=label + ":", font=('Arial', 10)).grid(row=i, column=0, sticky="e", padx=10, pady=5)
    entry = tk.Entry(frame_inputs, font=('Arial', 10), width=25)
    entry.grid(row=i, column=1, pady=5)
    entries.append(entry)

entry_name, entry_pet, entry_year, entry_number, entry_custom = entries

tk.Button(tab2, text="Generate Wordlist", font=('Arial', 11), command=generate_wordlist_gui).pack(pady=20)

root.mainloop()
