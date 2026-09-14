🛡️ Chakravyuh: AI-Based Malware Behavioral Classifier
![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Machine Learning](https://img.shields.io/badge/Machine_Learning-Random_Forest-FF6F00?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Vercel](https://img.shields.io/badge/Deployed_on-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)
Hey everyone! 👋 This is my hackathon project for the AI & Threat Intelligence track.

I built Chakravyuh (which means an inescapable defensive formation) to solve a huge problem in modern cybersecurity: how do we catch malware that constantly changes its disguise?

🛑 The Problem (Why traditional Antivirus fails)
The old way of stopping malware is basically checking a list of known "bad" file signatures or hashes (like a bouncer checking IDs). But hackers figured this out a long time ago.

Today, attackers use "polymorphic" techniques to scramble their code slightly for every single attack. This generates a brand-new hash every time, making traditional Antivirus completely blind. Worse, a lot of modern malware doesn't even use files—they run entirely in the computer's memory (RAM) and hijack legitimate Windows tools (like PowerShell) to do their dirty work.

If there is no recognized file to scan, standard security tools just let it pass.

💡 The Solution (What I built)
Instead of looking at what a file looks like (its hash), Chakravyuh looks at what a file does (its behavior).

Even if a hacker scrambles their code to look completely new, the malware still has to perform the same actions to succeed—like encrypting files, modifying registry keys to survive a reboot, or secretly talking to a hacker's server.

Chakravyuh acts as a dynamic analysis dashboard. Here is what it does when you feed it a behavioral trace:

API Call Monitoring: It traces the exact sequence of Windows system calls the program makes.

AI Classification: It uses machine learning to categorize the behavior into specific families (Is this acting like Ransomware? A Trojan? A Worm?).

Process Tree Mapping: It visually maps out how the malware spreads (e.g., seeing a harmless-looking PDF suddenly open the command prompt).

MITRE ATT&CK Translation: It automatically translates the malicious actions into standard cybersecurity threat tactics (like spotting T1055: Process Injection) so security analysts know exactly what they are dealing with.

🛠️ How it works (The Tech)
For this hackathon prototype, I built it using a single-file architecture to make it incredibly easy to run and demo locally or on a virtual machine.

Backend: Python + FastAPI

Frontend: A dark-mode, cyberpunk-themed UI built with React/HTML and Tailwind CSS (served directly from the Python backend so there are zero CORS issues).

Demo Data: To avoid the risks of running live polymorphic zero-days on a hackathon network, the prototype uses pre-captured dynamic API execution traces (mocked via JSON/filenames for the live demo) to showcase the analysis engine.

Feel free to check out the code, drop a file in the UI, and watch the matrix catch it!
