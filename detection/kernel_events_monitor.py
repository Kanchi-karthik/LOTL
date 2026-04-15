import time
from collections import defaultdict

class KernelEventMonitor:
    """
    Analyzes kernel-level events from Falco to detect file-less attacks.
    Enhances the base command-string detection with syscall context.
    """
    
    def __init__(self):
        self.process_tree = defaultdict(list)
        self.suspicious_patterns = {
            'memfd_create': 'File-less execution via memory file',
            'process_vm_writev': 'Process memory injection',
            'ptrace': 'Debugger attachment (possible injection)',
            'bpf': 'eBPF program loading (potential rootkit)',
            'init_module': 'Kernel module loading',
            'finit_module': 'Kernel module loading',
            'execve': 'Process execution',
            'connect': 'Outbound network connection'
        }
    
    def analyze_event(self, event_data):
        """
        Analyze structured Falco event for file-less attack patterns.
        event_data is expected to be a dictionary from the Falco JSON.
        """
        alerts = []
        
        # Falco JSON usually has 'evt.type' or similar depending on output template
        # We'll check common fields
        syscall = event_data.get('evt_type') or event_data.get('rule')
        cmdline = event_data.get('output_fields', {}).get('proc.cmdline', '')
        container = event_data.get('output_fields', {}).get('container.name', 'unknown')
        
        # 1. memfd_create - File-less execution
        if syscall == 'memfd_create':
            alerts.append({
                'severity': 'CRITICAL',
                'type': 'fileless_execution',
                'description': 'Anonymous memory file created - potential file-less malware',
                'mitre_technique': 'T1059.004',
                'mitre_name': 'Command and Scripting Interpreter'
            })
        
        # 2. Process injection via ptrace
        if syscall == 'ptrace' and ('PTRACE_POKETEXT' in str(event_data) or 'PTRACE_ATTACH' in str(event_data)):
            alerts.append({
                'severity': 'CRITICAL',
                'type': 'process_injection',
                'description': 'Process memory modification or attachment detected',
                'mitre_technique': 'T1055.008',
                'mitre_name': 'Process Injection: Ptrace System Calls'
            })
        
        # 3. Unusual shell patterns (enhancing RealtimeDetector)
        if cmdline:
            cmd_lower = cmdline.lower()
            
            # Pattern: curl | bash (pipe to shell)
            if 'curl' in cmd_lower and '|' in cmd_lower and ('bash' in cmd_lower or 'sh' in cmd_lower):
                alerts.append({
                    'severity': 'HIGH',
                    'type': 'fileless_download',
                    'description': f'Download and execute without writing to disk: {cmdline}',
                    'mitre_technique': 'T1105',
                    'mitre_name': 'Ingress Tool Transfer'
                })
            
            # Pattern: python -c "exec(urllib..."
            if 'python' in cmd_lower and 'exec' in cmd_lower and ('url' in cmd_lower or 'requests' in cmd_lower):
                alerts.append({
                    'severity': 'HIGH',
                    'type': 'python_fileless',
                    'description': f'Python executing remote code: {cmdline}',
                    'mitre_technique': 'T1059.006',
                    'mitre_name': 'Python'
                })
        
        # 4. Kernel module loading
        if syscall in ['init_module', 'finit_module']:
            alerts.append({
                'severity': 'CRITICAL',
                'type': 'kernel_module',
                'description': f'Kernel module loading detected: {syscall}',
                'mitre_technique': 'T1547.006',
                'mitre_name': 'Kernel Modules and Extensions'
            })
        
        return alerts
    
    def track_process_chain(self, event_data):
        """
        Track process relationships to detect suspicious chains.
        """
        ppid = event_data.get('output_fields', {}).get('proc.ppid')
        pid = event_data.get('output_fields', {}).get('proc.pid')
        cmd = event_data.get('output_fields', {}).get('proc.cmdline', '')
        
        if not ppid or not pid:
            return None
            
        # Build process tree (simplified for demo)
        self.process_tree[ppid].append({
            'pid': pid,
            'command': cmd,
            'timestamp': time.time()
        })
        
        # Look for suspicious chains like bash -> curl -> bash
        # This is a bit complex for a stateless stream, but we can look at recent children
        children = self.process_tree[ppid]
        if len(children) >= 3:
            cmds = [c['command'].split()[0] for c in children[-3:] if c['command']]
            if 'bash' in cmds and 'curl' in cmds and 'bash' in cmds:
                return {
                    'alert': True,
                    'reason': 'Suspicious process chain: bash -> curl -> bash (download-execute pattern)',
                    'container': event_data.get('output_fields', {}).get('container.name')
                }
        
        return None

# Singleton instance
kernel_monitor = KernelEventMonitor()
