#!/usr/bin/env python3
"""
SSH Honeypot Log Analysis Tool
Analyzes Cowrie honeypot logs to extract threat intelligence
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import requests
import re
from datetime import datetime
import os
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA

class SSHHoneypotAnalyzer:
    def __init__(self, log_file_path, output_folder="results"):
        self.log_file = log_file_path
        self.output_folder = output_folder
        os.makedirs(self.output_folder, exist_ok=True)
        self.data = []
        self.df = None

    def load_logs(self):
        print("Loading honeypot logs...")
        with open(self.log_file, 'r') as f:
            content = f.read().strip()

        try:
            data = json.loads(content)
            if isinstance(data, list):
                for session_data in data:
                    if isinstance(session_data, dict):
                        for session_id, events in session_data.items():
                            if isinstance(events, list):
                                self.data.extend(events)
                            else:
                                self.data.append(events)
            elif isinstance(data, dict):
                for session_id, events in data.items():
                    if isinstance(events, list):
                        self.data.extend(events)
                    else:
                        self.data.append(events)
            print(f"Loaded {len(self.data)} log entries (nested format)")
            return len(self.data)
        except json.JSONDecodeError:
            pass

        try:
            lines = content.split('\n')
            for line in lines:
                if line.strip():
                    try:
                        log_entry = json.loads(line.strip())
                        self.data.append(log_entry)
                    except json.JSONDecodeError:
                        continue
            print(f"Loaded {len(self.data)} log entries (standard format)")
            return len(self.data)
        except Exception as e:
            print(f"Error loading logs: {e}")
            return 0

    def parse_login_attempts(self):
        login_attempts = []
        for entry in self.data:
            if entry.get('eventid') in ['cowrie.login.success', 'cowrie.login.failed']:
                src_ip = entry.get('src_ip') or entry.get('src_ip_identifier', 'unknown')
                attempt = {
                    'timestamp': entry.get('timestamp'),
                    'src_ip': src_ip,
                    'username': entry.get('username'),
                    'password': entry.get('password'),
                    'success': entry.get('eventid') == 'cowrie.login.success',
                    'session_id': entry.get('session_id'),
                    'country': entry.get('geolocation_data', {}).get('country_name', 'Unknown')
                }
                login_attempts.append(attempt)
        self.df = pd.DataFrame(login_attempts)
        print(f"Found {len(login_attempts)} login attempts")
        return self.df

    def get_ip_geolocation(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('country', 'Unknown')
        except:
            pass
        return 'Unknown'

    def enrich_with_geolocation(self):
        if self.df is None or self.df.empty:
            print("No data to enrich")
            return
        print("Enriching data with geolocation...")
        if 'country' in self.df.columns and self.df['country'].notna().any():
            print("Using existing geolocation data from logs")
            return
        unique_ips = self.df['src_ip'].unique()
        ip_to_country = {}
        for ip in unique_ips[:50]:
            if ip != 'unknown' and not ip.startswith('src_ip_identifier'):
                country = self.get_ip_geolocation(ip)
                ip_to_country[ip] = country
                print(f"IP: {ip} -> {country}")
        if ip_to_country:
            self.df['country'] = self.df['src_ip'].map(ip_to_country).fillna(self.df.get('country', 'Unknown'))

    def analyze_attack_patterns(self):
        if self.df is None or self.df.empty:
            print("No data to analyze")
            return {}
        analysis = {
            'top_countries': self.df['country'].value_counts().head(10).to_dict(),
            'top_usernames': self.df['username'].value_counts().head(10).to_dict(),
            'top_passwords': self.df['password'].value_counts().head(10).to_dict(),
            'top_ips': self.df['src_ip'].value_counts().head(10).to_dict(),
            'success_rate': (self.df['success'].sum() / len(self.df)) * 100 if len(self.df) > 0 else 0
        }
        return analysis

    def parse_commands(self):
        commands = []
        for entry in self.data:
            if entry.get('eventid') == 'cowrie.command.input':
                src_ip = entry.get('src_ip') or entry.get('src_ip_identifier', 'unknown')
                cmd = {
                    'timestamp': entry.get('timestamp'),
                    'src_ip': src_ip,
                    'command': entry.get('input', ''),
                    'session': entry.get('session') or entry.get('session_id')
                }
                commands.append(cmd)
        return pd.DataFrame(commands)

    def analyze_commands(self):
        cmd_df = self.parse_commands()
        if cmd_df.empty:
            return {}
        suspicious_patterns = ['wget', 'curl', 'nc', 'netcat', 'bash', 'sh', 'python', 'perl', 'base64', 'chmod +x']
        suspicious_commands = []
        for pattern in suspicious_patterns:
            matches = cmd_df[cmd_df['command'].str.contains(pattern, case=False, na=False)]
            suspicious_commands.extend(matches['command'].unique().tolist())
        return {
            'top_commands': cmd_df['command'].value_counts().head(15).to_dict(),
            'suspicious_commands': suspicious_commands[:10],
            'total_commands': len(cmd_df),
            'unique_commands': cmd_df['command'].nunique()
        }

    def generate_visualizations(self):
        if self.df is None or self.df.empty:
            print("No data for visualization")
            return
        plt.style.use('default')
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        fig.suptitle('SSH Honeypot Attack Analysis', fontsize=16)
        top_countries = self.df['country'].value_counts().head(8)
        axes[0,0].bar(top_countries.index, top_countries.values)
        axes[0,0].set_title('Top Attacking Countries')
        axes[0,1].bar(self.df['username'].value_counts().head(8).index,
                     self.df['username'].value_counts().head(8).values)
        axes[0,1].set_title('Most Targeted Usernames')
        success_counts = self.df['success'].value_counts()
        axes[1,0].pie(success_counts.values, labels=['Failed', 'Success'], autopct='%1.1f%%')
        axes[1,0].set_title('Login Success Rate')
        if 'timestamp' in self.df.columns:
            self.df['hour'] = pd.to_datetime(self.df['timestamp']).dt.hour
            hourly_attacks = self.df['hour'].value_counts().sort_index()
            axes[1,1].plot(hourly_attacks.index.to_numpy(), hourly_attacks.values, marker='o')
            axes[1,1].set_title('Attacks by Hour of Day')
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_folder, 'honeypot_analysis.png'), dpi=300, bbox_inches='tight')
        print("Visualizations saved")

    def behavioral_clustering(self):
        if self.df is None or self.df.empty:
            print("No data for clustering")
            return

        df = self.df.copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour

        grouped = df.groupby('src_ip').agg({
            'timestamp': 'count',
            'username': pd.Series.nunique,
            'password': pd.Series.nunique,
            'success': lambda x: (x == True).sum(),
            'hour': lambda x: x.mode()[0] if not x.mode().empty else -1
        })

        grouped.columns = ['num_attempts', 'unique_usernames', 'unique_passwords', 'successful_attempts', 'peak_hour']
        grouped['success_ratio'] = grouped['successful_attempts'] / grouped['num_attempts']
        grouped = grouped.drop(columns='successful_attempts')

        features = grouped[['num_attempts', 'unique_usernames', 'unique_passwords', 'success_ratio', 'peak_hour']]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(features)

        kmeans = KMeans(n_clusters=4, random_state=42)
        grouped['cluster'] = kmeans.fit_predict(X_scaled)

        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled)
        grouped['pca1'] = X_pca[:, 0]
        grouped['pca2'] = X_pca[:, 1]

        plt.figure(figsize=(10, 7))
        sns.scatterplot(data=grouped, x='pca1', y='pca2', hue='cluster', palette='tab10')
        plt.title("Attacker Behavioral Clusters (PCA)")
        plt.xlabel("PCA Component 1")
        plt.ylabel("PCA Component 2")
        plt.savefig(os.path.join(self.output_folder, "attacker_clusters.png"))
        plt.show()

    def generate_report(self):
        print("\n" + "="*60)
        print("SSH HONEYPOT THREAT ANALYSIS REPORT")
        print("="*60)
        print(f"\nTotal log entries: {len(self.data):,}")
        print(f"Login attempts: {len(self.df):,}")
        if self.df is not None and not self.df.empty:
            print(f"Unique source IPs: {self.df['src_ip'].nunique():,}")
            print(f"Unique usernames: {self.df['username'].nunique():,}")
            print(f"Unique passwords: {self.df['password'].nunique():,}")
            patterns = self.analyze_attack_patterns()
            print(f"Success rate: {patterns['success_rate']:.2f}%")
            print("\nTop Countries:")
            for k, v in patterns['top_countries'].items():
                print(f"  {k}: {v}")
        cmd_analysis = self.analyze_commands()
        if cmd_analysis:
            print("\nSuspicious Commands:")
            for cmd in cmd_analysis['suspicious_commands']:
                print(f"  {cmd}")
        print("\n" + "="*60)

    def export_results(self):
        if self.df is not None and not self.df.empty:
            self.df.to_csv(os.path.join(self.output_folder, 'login_attempts.csv'), index=False)
            print("Login attempts saved")
            patterns = self.analyze_attack_patterns()
            summary_df = pd.DataFrame([
                ['Total Login Attempts', len(self.df)],
                ['Unique IPs', self.df['src_ip'].nunique()],
                ['Success Rate %', f"{patterns['success_rate']:.2f}"]
            ], columns=['Metric', 'Value'])
            summary_df.to_csv(os.path.join(self.output_folder, 'analysis_summary.csv'), index=False)
            print("Summary saved")
        cmd_df = self.parse_commands()
        if not cmd_df.empty:
            cmd_df.to_csv(os.path.join(self.output_folder, 'executed_commands.csv'), index=False)
            print("Commands saved")

    def run_full_analysis(self):
        print("Starting SSH Honeypot Analysis...")
        self.load_logs()
        self.parse_login_attempts()
        if self.df is not None and not self.df.empty:
            self.enrich_with_geolocation()
            self.generate_visualizations()
            self.behavioral_clustering()
            self.generate_report()
            self.export_results()
        else:
            print("No login attempts found")

if __name__ == "__main__":
    log_folder = "logs"
    output_folder = "results"
    os.makedirs(output_folder, exist_ok=True)
    combined_logs = []
    for filename in os.listdir(log_folder):
        if filename.endswith(".json"):
            with open(os.path.join(log_folder, filename), 'r') as f:
                combined_logs.append(f.read())
    combined_path = os.path.join(output_folder, "combined_logs.json")
    with open(combined_path, 'w') as f:
        f.write("\n".join(combined_logs))
    analyzer = SSHHoneypotAnalyzer(combined_path, output_folder)
    analyzer.run_full_analysis()
