# Password Hashing Evaluator
CIS 4378 – Spring 2026  
Amir Ibrahim, Arman Briones, Kyle Stressman, Prem Patel  

## What this does
This script compares three password hashing algorithms:
- Argon2id  
- bcrypt  
- PBKDF2  

It checks how long each one takes to hash a password and estimates how long brute force would take.

## How it works
- Uses 15 passwords split into weak, medium, and strong  
- Hashes each password with all three algorithms  
- Measures hash time  
- Estimates crack time  

## How to run
Install packages:
pip install bcrypt argon2-cffi

Run the script:
python evaluator.py
