# Calico


## Installation

Methods of installation:

<img width="750" alt="image" src="https://github.com/user-attachments/assets/7ba68ea4-629c-42b3-addd-b0e17746afb3">


Kubernetes: https://docs.tigera.io/calico/latest/getting-started/kubernetes/

## Calico in Kubernetes

Core Principles
1.  Every pod gets its own IP address.
2.  Containers within the pod can share that IP address and communicate freely with each other.
3.  Pods can commuincate with other pods in cluster using the IP address without (NAT) Network Adress Translation. That is the IPs are preserved across the pod network.
4.  Network Isolation that restict each pod can communicate with defines using Network Policy.

<img width="1031" alt="image" src="https://github.com/user-attachments/assets/610d5cf4-3539-4531-92e3-9e7f8b9cd3e0">

### Kubernetes Network Implementation

**KubeNet** is default network solution in K8s which provides the basic network connectivity.

Calico is 3rd party Network Implementation in K8s which can be plugged in using CNI [Container Network Interface] API. 
CNI config files are used to determine which CNI plugins to run.

Different kinds of CNI plugins can be chained together.

 For Example:
 1. Network Connecivity - Calico Network Plugin.
 2. IP Address Management (IPAM) - Calico IPAM Plugin.
 3. Network Policy Management.
 4. Perfomance & Encryption.

## Workflow -
Pod IP allocation
1. When a new pod is created in K8s, Kubelet call the Calico Network Plugin.
2. The Calico Network Plugin invokes the Calico IPAM Plugin.
3. The IPAM Plugin allocates the IP address for the pod and returns the IP to the Network plugin.
4. The Network plugin set the pod's Networking with the new IP address allocated and connects it to the  K8s pod network.
5. After updating the pod resource, the IP details are shared with kubelet.
<br>
  <img width="1031" alt="image" src="https://github.com/user-attachments/assets/93adab3a-7e69-42a3-9aec-0334d1869a16">


Calico's flexible design allows it to run with a range other CNI plugins.<br>
For Example:
1. Host-Local IPAM CNI Plugin, used by GKE.
2. Amazon CNI Plugin.
3. Azure CNI Plugin.
