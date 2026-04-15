import subprocess
import threading
import queue
import time
import json
import os
from kubernetes import client, config, watch

class RealK8sMonitor:
    def __init__(self):
        # Load Kubernetes config
        try:
            config.load_incluster_config()
        except Exception:
            try:
                config.load_kube_config()
            except Exception as e:
                print(f"Warning: Could not load Kubernetes config: {e}")
        
        try:
            self.core_v1 = client.CoreV1Api()
            self.networking_v1 = client.NetworkingV1Api()
        except Exception:
            self.core_v1 = None
            self.networking_v1 = None
            
        self.log_queue = queue.Queue()
        self.running = False
        
    def start_streaming(self):
        """
        Start streaming REAL Falco logs from Kubernetes cluster in a background thread
        """
        if not self.core_v1:
            print("Kubernetes API client not initialized.")
            return
            
        self.running = True
        thread = threading.Thread(target=self._stream_falco_logs_loop, daemon=True)
        thread.start()
        return thread

    def _stream_falco_logs_loop(self):
        while self.running:
            try:
                # Get Falco pods
                pods = self.core_v1.list_namespaced_pod(
                    namespace='falco',
                    label_selector='app.kubernetes.io/name=falco'
                )
                
                if not pods.items:
                    print("No Falco pods found in 'falco' namespace.")
                    time.sleep(10)
                    continue
                    
                for pod in pods.items:
                    # Stream logs from each Falco pod
                    w = watch.Watch()
                    for line in w.stream(
                        self.core_v1.read_namespaced_pod_log,
                        name=pod.metadata.name,
                        namespace='falco',
                        container='falco',
                        follow=True,
                        tail_lines=10
                    ):
                        if not self.running:
                            break
                        self.log_queue.put(line)
                        
            except Exception as e:
                print(f"Error streaming Falco logs: {e}")
                time.sleep(5)
    
    def get_running_containers(self):
        """
        Get all running containers in the cluster
        """
        if not self.core_v1:
            return []
            
        containers = []
        try:
            pods = self.core_v1.list_pod_for_all_namespaces()
            for pod in pods.items:
                for container in pod.spec.containers:
                    containers.append({
                        'pod': pod.metadata.name,
                        'namespace': pod.metadata.namespace,
                        'container': container.name,
                        'image': container.image,
                        'status': pod.status.phase
                    })
        except Exception as e:
            print(f"Error listing pods: {e}")
            
        return containers
    
    def execute_in_container(self, pod_name, namespace, command):
        """
        Execute a command in a container (for response)
        """
        if not self.core_v1:
            return "Error: K8s client not initialized"
            
        try:
            from kubernetes.stream import stream
            exec_command = ['/bin/sh', '-c', command]
            resp = stream(self.core_v1.connect_get_namespaced_pod_exec,
                pod_name,
                namespace,
                command=exec_command,
                stderr=True, stdin=False,
                stdout=True, tty=False)
            return resp
        except Exception as e:
            return f"Error: {e}"
    
    def quarantine_pod(self, pod_name, namespace):
        """
        Quarantine a pod by adding a label and a blocking NetworkPolicy
        """
        if not self.core_v1 or not self.networking_v1:
            return False
            
        try:
            # 1. Add Label
            body = {"metadata": {"labels": {"quarantined": "true"}}}
            self.core_v1.patch_namespaced_pod(pod_name, namespace, body)
            
            # 2. Add NetworkPolicy
            policy_name = f"quarantine-{pod_name}"
            policy = client.V1NetworkPolicy(
                api_version="networking.k8s.io/v1",
                kind="NetworkPolicy",
                metadata=client.V1ObjectMeta(name=policy_name, namespace=namespace),
                spec=client.V1NetworkPolicySpec(
                    pod_selector=client.V1LabelSelector(match_labels={"quarantined": "true"}),
                    policy_types=["Ingress", "Egress"],
                    ingress=[], # Block all
                    egress=[]   # Block all
                )
            )
            try:
                self.networking_v1.create_namespaced_network_policy(namespace, policy)
            except Exception as e:
                if "AlreadyExists" in str(e):
                    self.networking_v1.replace_namespaced_network_policy(policy_name, namespace, policy)
                else:
                    raise e
            return True
        except Exception as e:
            print(f"Error quarantining pod {pod_name}: {e}")
            return False

    def release_pod(self, pod_name, namespace):
        """
        Release a pod from quarantine
        """
        if not self.core_v1 or not self.networking_v1:
            return False
            
        try:
            # 1. Remove Label
            body = {"metadata": {"labels": {"quarantined": None}}}
            self.core_v1.patch_namespaced_pod(pod_name, namespace, body)
            
            # 2. Delete NetworkPolicy
            policy_name = f"quarantine-{pod_name}"
            try:
                self.networking_v1.delete_namespaced_network_policy(policy_name, namespace)
            except Exception as e:
                if "NotFound" not in str(e):
                    print(f"Non-critical error deleting network policy: {e}")
            return True
        except Exception as e:
            print(f"Error releasing pod {pod_name}: {e}")
            return False

# Singleton instance
k8s_monitor = RealK8sMonitor()
