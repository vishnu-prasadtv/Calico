# Calico in Kubernetes 

*Kubernetes Network Model:*

Core Principles
1.  Every pod gets its own IP address.
2.  Containers within the pod can share that IP address and communicate freely with each other.
3.  Pods can communicate with other pods in cluster using the IP address without (NAT) Network Adress Translation. That is the IPs are preserved across the pod network.
4.  Network Isolation that restrict each pod can communicate with defines using Network Policy.
5.  Referred as Flat Network. This simplifies the network, and allows new workloads to be scheduled dynamically anywhere in the cluster with no dependecies on the network design
6.  Security is defined by Network Policy instead of conventional Network Topology.
7.  The Kubernetes network model requires L3 (IP) connectivity only. Pods may be in the same CIDR, but are normally not strictly in the same subnet as they don't have L2 connectivity.
8.  Kubernetes supports network plugins using CNI API.


## Kubernetes Network Implementation 

**KubeNet** is default network solution in K8s which provides the basic network connectivity.

Calico is 3rd party Network Implementation in K8s which can be plugged in using CNI [Container Network Interface] API. 
CNI config files are used to determine which CNI plugins to run.

Different kinds of CNI plugins can be chained together.
*For Example:*
 1. Network Connecivity - Calico Network Plugin.
 2. IP Address Management (IPAM) - Calico IPAM Plugin.
 3. Network Policy Management.
 4. Perfomance & Encryption.

## Workflow - Pod IP allocation  

1. When a new pod is created in K8s, Kubelet call the Calico Network Plugin.
2. The Calico Network Plugin invokes the Calico IPAM Plugin.
3. The IPAM Plugin allocates the IP address for the pod and returns the IP to the Network plugin.
4. The Network plugin set the pod's Networking with the new IP address allocated and connects it to the  K8s pod network.
5. After updating the pod resource, the IP details are shared with kubelet.

Calico's flexible design allows it to run with a range other CNI plugins.<br>
For Example:
1. Host-Local IPAM CNI Plugin, used by GKE.
2. Amazon CNI Plugin.
3. Azure CNI Plugin.

Where calico can provide the Network Policy and Complimentary Networking capabilities like Performance improvement and Encryption.

## Kubernetes Services

- K8s services provides a way of abstracting access to a group of pods as a networks service.
- Group of pods backing each service, is usually defined using Label selector.
- The Kubernetes network model does specify that pods can communicate with each other directly without NAT. But a pod communicating with another pod via a service is not direct communication, and **normally will use NAT to change the connection destination from the service to the backing pod as part of load balancing**.
- When a client connects to K8s service, the conection is intercepted and load balanced to one of the pods backing the service. as illustrated below:

![image](https://github.com/user-attachments/assets/74deed50-06d0-43a5-9c6a-fc7bed581290)

#  Types of services

**ClusterIP Service**
- Is the usual way of accessing services from inside the cluster.
- ClusterIP is the virtual IP adrdess used to represent the service.
- The Pod can find the ClusterIP using DNS.
- The Client Pod-A tries to connect to the ClusterIP, then thhe Kube-Proxy intercepts the connection, and load balances the it to one of the destination Pod-B.

![image](https://github.com/user-attachments/assets/d3999f46-9319-45af-aa22-92da7756afff)

**NodePort Services**
- Is the Basic way of accessing a service from outside of the cluster.
- Node port is a port reserved on each node in the cluster through which the service can be accessed.
- Here a client outside cluster can connect to the node port on any if the Nodes in the cluster.
- Then the Kube-Proxy will intercept the connection, and load balance it to a backing Pod.

![image](https://github.com/user-attachments/assets/bbc3545f-cfe2-4895-b982-d4983655329c)

**LoadBalancer Services**

- This service use a Load balancer as a layer infront of the Node Ports, to provide a more sophistaicated way to access the cluster from outside.

![image](https://github.com/user-attachments/assets/75622f0c-ac1b-48dc-bbd9-c0457f85b160)

## Kubernetes DNS
- It is the built-in DNS service in K8s.
- It is implemented as a K8s service, that maps to one or more DNS server pods, usually running CoreDNS pods.
- Every Pods and Service is discoverable though the Kubernetes DNS service.

For example- 
- Querying a service name returns the service ClusterIP.
- The pods in the cluster are configured with a DNS search list that includes the pod's own namespace and the cluster's default domain name.
   - If the pod is in the same namespace as the service, it can just use the service's name without needing to know which namespace and which cluster its running in.

![image](https://github.com/user-attachments/assets/92d608d1-d760-4d2d-b830-607f50a278c1)


## Outgoing NAT

**Example:**

If the pod network is an Overlay network, when a pod tries to connect to an external server outside the cluster:
- The connection is intercepted and the Network Address Translation is used to map the pod's source IP to node's IP.
- The packet can then traverse rest of the external network to where ever the destination is.
- The return packets on the connection can get mapped back automatically from the nodeIP back to the Pod IP address.
- And the external server is unaware that its talking to a pod, rather than to a node.

![image](https://github.com/user-attachments/assets/ed03d8dd-bc7c-48f0-8725-0d46bf15eca8)

## IPV6 and Dual stack

- In case of Dual stack all pods will be assigned with an IPV4 address and a IPV6 address.
- And each K8s service can be specified if needs to  be exposed to IPV4 or IPV6.
- Calico supports IPV4, IPV6 and Dual stack.


# Network Policy

- Is the Primary tool used for securing a Kubernetes network.
- It allows you to easily restrict the network traffic in you cluster.
- So only the desired traffic is allowed.

### History of Network Security

- In enterprise env, the security was provided by designing a physical topology of network devices such as SWITCHES, ROUTERS and FIREWALLS.
- Adding new application or services often required additional network design to update the network topology to provide the desired security.

![image](https://github.com/user-attachments/assets/c2b3256b-30a5-4b15-8e42-720a71c5a4da)

## Features of Network Policy?

- Referred as Flat Network. This simplifies the network, and allows new workloads to be scheduled dynamically anywhere in the cluster with no dependecies on the network design
- Security is defined by Network Policy instead of conventional Network Topology.
- Network Policies are further abstracted from network, by using label selectors as their primary mechanism for identifying workloads rather than IP address ranges.
- K8s defines a standard network policy API, so there is a base set of features

![image](https://github.com/user-attachments/assets/10c6d1a3-9e7a-45a9-b194-7fa67f143695)

## Why Network Policy?

- Cyber atacks are more sophisticated and more in volume.
- Traditional firewalls struggle with Dynamic nature of K8s.
- Now in K8s you can use Firewalls at the perimeter to help secure the north-south traffic [Client-Cluster communication].
- Security can be coarse-grained using IP address range of the whole cluster.
- Calico Enterprise can be integrated with Fortinet firewalls, so as to understand the ingress node or pod IP addresses.
- But these firewalls are not suitable for the east-west traffic enforcement within the cluster.

- Network policy is label selector based -> inherently dynamic.

- Empowers teams to adopt "shift left" security practices- Developers and operations teams who are not networking experts have the ability to implement security themselves.

## Kubernetes Network Policy
- The API group belongs to the **networking.k8s.io/v1**
- It is namespaced.
- The Pod selectore defines the pods that the policy applues to.
- Have the series of ingress and egress rules or both.  
- They typicall use pod selectors to identify the other pods in cluster.
   
![image](https://github.com/user-attachments/assets/3329f3e4-0889-424b-9f27-c6d5962738b5)

### Common Network policy rules:
1. Default deny all ingress traffic 

```
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

2. Allow all ingress traffic 
```
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
spec:
  podSelector: {}
  ingress:
  - {}
  policyTypes:
  - Ingress
```

3. Default deny all egress traffic 
```
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

4. Allow all egress traffic 
```
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-egress
spec:
  podSelector: {}
  egress:
  - {}
  policyTypes:
  - Egress
```

5. Default deny all ingress and all egress traffic 
```
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

Referende link [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

## Calico Network Policy

- Calico support 2 types of  Network policies:
  1. Networkpolicy  
     - The API group belongs to the **projectcalico.org/v3**
     - It is Namespaced.
     - Use label sector to define to which pods the policies are applied to.
     - With series of Ingress/Egress rules.
     - The implicit action is to ALLOW in Caclico Network policy, as compared to K8s network policy where its to deny.
     - Calico allows you to Explicitly specify ALLOW or DENY actions.
     - Calico also allows you to specify precedence order for the policy. This is important when multiple policies are applied to the same pod, and one of them says allow and other say deny.
     - The Order field determines which policy will actually take action.
     - Additional options to match pods based on the service account.
     - K8s Network policies can only select pods , whereas the Calico network policy rules can identify other types of objects including Calico Network sets and Host Endpoints.

![image](https://github.com/user-attachments/assets/ce5d052f-f463-4c13-a45d-a260af8bdc15)
 
 2. GlobalNetworkPolicy 
     - The API group belongs to the **projectcalico.org/v3**
     - It is NON-Namespaced- Global Network policy that applies across the whole cluster.
     - Use label sector to define to which pods the policies are applied to.
     - With series of Ingress/Egress rules.
     - The implicit action is to ALLOW in Calico Network policy, as compared to K8s network policy where its to deny.
     - Calico allows you to Explicitly specify ALLOW or DENY actions.
     - Calico also allows you to specify precedence order for the policy. This is important when multiple policies are applied to the same pod, and one of them says allow and other say deny.
     - The Order field determines which policy will actually take action.
     - Additional options to match pods based on the serviceaccount.
     - K8s Network policies can only select pods , whereas the Calico network policy rules can identify other types of objects including Calico Network sets and Host Endpoints.

![image](https://github.com/user-attachments/assets/b47fac7b-4036-440f-8106-31b9e7c1e067)

### Calico objects:

   ![image](https://github.com/user-attachments/assets/6dce2d7a-bd0f-4b24-bedd-538c06a23330)


## Calico Network Policy    Vs     Kubernetes Network Policy

- Calico implements every K8s Network Policy features, with many other implementations and gap within the K8s N/W-Policy which results in policies not behaving as expected in production environments.
- Calico is used as an reference implementation during the development of the K8s N/W-Policy API.
- Calico provides its own network policy capabilities with a richer set of features that enable more advanced use cases.
  
  ![image](https://github.com/user-attachments/assets/6a979c5d-ff06-48fc-b6b3-e1edd45fae2e)


- It is possible to use K8s and Calico Network policies side by side. 
For example:
  - Your developement team might use K8s Network policies to define per micro service policy rules. This is the base usecase the K8s Network policies is designed for.
  - The Security or Platform team may use Calico network policies, to define the cluster's overall security posture. 
        Such as: 
          - Denying any traffic which is not specifically allowed by a network policy,
          - Limiting egress from the cluster.
          - Ensuring metrics can always be gathered.

       ![image](https://github.com/user-attachments/assets/e52fea48-455b-4226-8886-013d17124fe5)

## Host Endpoints

**Ability to Protect Hosts**   

- Network Policy can be thought of providing a firewall infront of every pods that is built into the pod network.
- Calico can take that a sted further and use network policy to help secure the nodes themselves.
- Similar to putting a firewall on every one the node's network interfaces.
- Calico refers to this end points as Host Endpoints.
- Endpoints can be labeled just like pods, and network policy applies to them based on their labels.      

![image](https://github.com/user-attachments/assets/899c5a19-fcb6-46e2-8b41-6d4930b9ddd3)


## ISTIO Integration

- Calico can enforce network policy within an ISTIO service mesh.
- This includes matching on application layer attributes, such as http methods and paths.
- It uses cryptographic identity associated with each part in the service mesh as additional authentication for any traffic.
- Enforcing policy at the service mesh layer and the pod network layer provides defence in depth, as part of a zero trust network security model.

![image](https://github.com/user-attachments/assets/186b9491-4f25-4a26-8882-60ca125d4af1)

### Extendable with Calico Enterprise

Offer additional features like: 
- Heirarchical  policy.
- DNS based policy.
- Policy recommendation tools.
- Policy impact previews.
- Staging of policies,
- Visbility and alerting tools.
- Multicluster management features.
- Compliance, Threat defence.


## Best practices for Network Policies

- Restric tingress traffic.
- If an attacker manages to pass through ingress, to reduce further attack on other pods, restrict egress traffic.
- Always specify the ingress and egress rules in your network policy.
- Ensure every pods are covered by network policies.

### Policy and Label Schemas
- Standardise the way you label the pods and network policies.
- This makes easy to follow and understand.
- Use consistent scheme or design pattern.

![image](https://github.com/user-attachments/assets/d79cb191-deac-4b6b-b006-45f16d0f3864)

### Default deny
- K8s allow all traffic to the pod by default. This is risky from security pont of view.
- To avoid this put default deny policy that prevents any traffic which is not explicitly allowed by any other policy.
- This can be applied per namespace basis using K8s network policy.

![image](https://github.com/user-attachments/assets/3236e8c3-d1d5-49c6-bc83-2126fdcf3227)

- To avoid writing policy per namespace, you can use Calico Global Network policy that applies across the whole of the cluster.
- Caution- The above policy would also apply to any host endpoints, as well the K8s and Calico Control Planes.

![image](https://github.com/user-attachments/assets/14fd00ea-d0c7-4542-984c-588133183eba)

- To avoid this, apply the policy only to the Non-system [exclude K8s and Calico controleplane {"kube-system", "calico-system", "calico-apiserver"}] pods, using namespaceSelecor as shown below:
  
![image](https://github.com/user-attachments/assets/2630c08b-3271-4845-b2e4-a714a5c99448)


### Hierarchical Network Policy

- Split the security responsibilities across multple layers of teams.
- Similar to teams delegating trust to each other, within specific scopes they have defined.
- In the below example, the infosec team defines the guardrails for the platform team.
- And the platform team defines the gaurdrails for the individual service teams.

![image](https://github.com/user-attachments/assets/80f2b5cf-064f-4934-9be5-b7e0cbe84403)

# Scenarios

Assumes you already have the "Yet Another Online Bank" (yaobank) installed. Below is the architecture of YAOBank:

![image](https://github.com/user-attachments/assets/cd8b992f-a9cc-4e4f-8dfd-4c77a54b763f)


1. To simulate a compromise of the customer pod we will exec into the pod and attempt to access the database directly from there.

   ```
   kubectl exec -it $CUSTOMER_POD -n yaobank -c customer -- /bin/bash
   ```

From within the customer pod, we will now attempt to access the database directly, simulating an attack.  As the pod is not secured with NetworkPolicy, the attack will succeed and the balance of all users will be returned.

```
curl http://database:2379/v2/keys?recursive=true | python -m json.tool
Success!!
```

To protect the database, we will be using kubernetes policy.

```
cat <<EOF | kubectl apply -f -
---
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: database-policy
  namespace: yaobank
spec:
  podSelector:
    matchLabels:
      app: database
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: summary
    ports:
      - protocol: TCP
        port: 2379
  egress:
    - to: []
EOF
```
```
curl --connect-timeout 3 http://database:2379/v2/keys?recursive=true
Timeout!!
```

The above scenarios results in applying the Network policy to all the namespaces. Here is why Calico policy can be useful. Since Calico’s GlobalNetworkPolicy policies apply across all namespaces, you can write a single default-deny policy for the whole of your cluster. Like:

```
cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-app-policy
spec:
  namespaceSelector: has(projectcalico.org/name) && projectcalico.org/name not in {"kube-system", "calico-system", "calico-apiserver"}
  types:
  - Ingress
  - Egress
EOF
```
NOTE: The calicoctl utility is used to create and manage Calico resource types, as well as allowing you to run a range of other Calico specific commands. In this specific case, we are creating a GlobalNetworkPolicy (GNP).

2. Lets update our default policy to allow DNS to the cluster-internal kube-dns service. 
```
cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-app-policy
spec:
  namespaceSelector: has(projectcalico.org/name) && projectcalico.org/name not in {"kube-system", "calico-system"}
  types:
  - Ingress
  - Egress
  egress:
    - action: Allow
      protocol: UDP
      destination:
        selector: k8s-app == "kube-dns"
        ports:
          - 53
EOF
```

3. Define policies for the customer or summary pods to access the setup.
```
cat <<EOF | kubectl apply -f - 
---
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: customer-policy
  namespace: yaobank
spec:
  podSelector:
    matchLabels:
      app: customer
  ingress:
    - ports:
      - protocol: TCP
        port: 80
  egress:
    - to: []
---
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: summary-policy
  namespace: yaobank
spec:
  podSelector:
    matchLabels:
      app: summary
  ingress:
    - from:
      - podSelector:
          matchLabels:
            app: customer
      ports:
      - protocol: TCP
        port: 80
  egress:
    - to:
      - podSelector:
          matchLabels:
            app: database
      ports:
      - protocol: TCP
        port: 2379
EOF
```

4.  Create a Calico GlobalNetworkPolicy to restrict egress to the Internet to only pods that have a ServiceAccount that is labeled "internet-egress = allowed".
```
cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: egress-lockdown
spec:
  order: 600
  namespaceSelector: has(projectcalico.org/name) && projectcalico.org/name not in {"kube-system", "calico-system"}
  serviceAccountSelector: internet-egress not in {"allowed"}
  types:
  - Egress
  egress:
    - action: Deny
      destination:
        notNets:
          - 10.0.0.0/8
          - 172.16.0.0/12
          - 192.168.0.0/16
          - 198.18.0.0/15
EOF
```

Examine the policy above. While Kubernetes network policies only have Allow rules, Calico network policies also support Deny rules. As this policy has Deny rules in it, it is important that we set its precedence higher than the lazy developer's Allow rules in their Kubernetes policy. To do this we specify order value of 600 in this policy, which gives this higher precedence than Kubernetes Network Policy (which does not have the concept of setting policy precedence, and is assigned a fixed order value of 1000 by Calico - i.e, policy order 600 gets precedence over policy order 1000).

5. Grant Selective Cluster Egress

Now imagine there was a legitimate reason to allow connections from the customer pod to the internet. As we used a Service Account label selector in our egress policy rules, we can enable this by adding the appropriate label to the pod's Service Account.

```
kubectl label serviceaccount -n yaobank customer internet-egress=allowed
```

## Protecting Hosts

- The interfaces on the node are reprensted in the Calico resource model as Host Endpoints.
- In the below example, the host endopint applies to the node's interface to the underlying network eth0:
- The Network policies matches using the labels, and without needing any special host specific syntax within the network policy.

![image](https://github.com/user-attachments/assets/56b7d19b-826c-4fdc-9164-a4fbbc15770e)

- For all network interfaces, you can use wilcard *

![image](https://github.com/user-attachments/assets/765cbd4c-70d0-4430-bc14-ac772f18e0b9)

- The Calico Policy can also be used to protect the host interfaces in any standalone Linux node (such as a baremetal node, cloud instance or virtual machine)

- Host endpoints are non-namespaced. So in order to secure host endpoints we'll need to use Calico global network policies. whcih allows DNS but by default deny all other traffic.
- We’ll create a default-node-policy that allows processes running in the host network namespace to connect to each other, but results in default-deny behavior for any other node connections.

```
cat <<EOF| calicoctl apply -f -
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-node-policy
spec:
  selector: has(kubernetes.io/hostname)
  ingress:
  - action: Allow
    protocol: TCP
    source:
      nets:
      - 127.0.0.1/32
  - action: Allow
    protocol: UDP
    source:
      nets:
      - 127.0.0.1/32
EOF
```

- Create the Host Endpoints, allowing Calico to start policy enforcement on node interfaces.

```
calicoctl patch kubecontrollersconfiguration default --patch='{"spec": {"controllers": {"node": {"hostEndpoint": {"autoCreate": "Enabled"}}}}}'
```

- Verify:
```
calicoctl get heps
NAME               NODE
node2-auto-hep     node2
control-auto-hep   control
node1-auto-hep     node1
```

NOTE: Calico has a configurable list of “failsafe” ports which take precedence over any policy. These failsafe ports ensure the connections required for the host networked Kubernetes and Calico control planes processes to function are always allowed (assuming your failsafe ports are correctly configured). This means you don’t have to worry about defining policy rules for these. The default failsafe ports also allow SSH traffic so you can always log into your nodes.

### Lockdown Nodeport access

- To restrict who can access services from outside the cluster. Lock down all node port access, and selectively allow access to the customer front end.
- Kube-proxy load balances incoming connections to node ports to the pods backing the corresponding service. This process involves using DNAT (Destination Network Address Translation) to map the connection to the node port to a pod IP address and port.
- Calico GlobalNetworkPolicy allows you to write policy that is enforced before this translation takes place. i.e. Policy that sees the original node port as the destination, not the backing pod that is being load balanced to as the destination. 

```
cat <<EOF | calicoctl apply -f -
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: nodeport-policy
spec:
  order: 100
  selector: has(kubernetes.io/hostname)
  applyOnForward: true
  preDNAT: true
  ingress:
  - action: Deny
    protocol: TCP
    destination:
      ports: ["30000:32767"]
  - action: Deny
    protocol: UDP
    destination:
      ports: ["30000:32767"]
EOF
```

Verify you cannot access yaobank frontend
```
curl --connect-timeout 3 198.19.0.1:30180
```

Selectively allow access to customer front end- Let’s update our policy to allow only host1 to access the customer node port:

```
cat <<EOF | calicoctl apply -f -
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: nodeport-policy
spec:
  order: 100
  selector: has(kubernetes.io/hostname)
  applyOnForward: true
  preDNAT: true
  ingress:
  - action: Allow
    protocol: TCP
    destination:
      ports: [30180]
    source:
      nets:
      - 198.19.15.254/32
  - action: Deny
    protocol: TCP
    destination:
      ports: ["30000:32767"]
  - action: Deny
    protocol: UDP
    destination:
      ports: ["30000:32767"]
EOF
```

Verify access for host1
```
curl 198.19.0.1:30180
```

# Introduction to pod connectivity

- Each node has its own IP, and is connected to the underlying network over a network interface: Eg: eth0.
- Pods also have its own IP address.
- The Pod's networking environment is isolated from the Host using Linux network Namespaces.
- The pods are connected to the Host using a pair virtual ethernet interfaces - veth pair.
- The pod see eth0 is their interface, and the host has an algorithmically generated interface name for each pod beginning with "cali".
- Calico sets up the host networking namespace to act as a virtual router.
- The local pods are connected to the virtual router.
- Calico make sure the virtual router knows where the all the pods are across the rest of the cluster.
- So calico can forward traffic to the right places.

![image](https://github.com/user-attachments/assets/8a02a630-35c2-4009-a696-574e80a51f13)

- The traffic between the same nodes are routed locally.

![image](https://github.com/user-attachments/assets/1bad419e-354c-4b09-9193-24add7efd14b)

- The traffic between pods on different nodes is routed over the underlying network.

![image](https://github.com/user-attachments/assets/380eb59d-36d8-48fa-9a54-487645c01698)


## IP-IP : VXLAN

- What happens when the underlying network DOES NOT know how to forward the pod traffic?
  -  In these cases we need to run an Overlay Network.
 
- Calico supports bothe VXLAN and IP-IP overlays.
- Implemented as Virtual Interfaces within the linux Kernel.

- When a pod sends a packet to a pod on a different node, the original package is encpasulated using VXLAN or IPIP into an outer packet using the node IP addresss.
- This hides the pod IPs of the original inner packet.
- The underlying network then just handles this as any other node to node traffic.
- On the receiving node, the VXLAN or IPIP packet is de-encpasulated to reveal the original packet, which is delivered to the destination pod.
- This is all don in Lnux Kernel.
- However, It is an overhead when you are running an Network intensive workloads.
- To avoid above drawback Calico support cross-subnet overlay modes, where the nodes in the same subnet can send pod traffic to each other without using an overlay.
- The overlay is only used when the pod traffic needs to flow between nodes in different subnets.
- So we get the best possible performance for each network flow, only using the overlay for the packets that actually need it.
- 

![image](https://github.com/user-attachments/assets/88907ac4-8c97-4998-9fb6-b5b4e3169991)

## Scenarios 

### How Pods See the Network

- Exec into pod:
- Checkout the interfaces:
  ```
  # ip addr
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
      link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
      inet 127.0.0.1/8 scope host lo
         valid_lft forever preferred_lft forever
      inet6 ::1/128 scope host
         valid_lft forever preferred_lft forever
    3: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1410 qdisc noqueue state UP group default
        link/ether 3a:0c:14:d0:92:89 brd ff:ff:ff:ff:ff:ff link-netnsid 0
        inet 198.19.22.132/32 brd 198.19.22.132 scope global eth0
           valid_lft forever preferred_lft forever
        inet6 fe80::380c:14ff:fed0:9289/64 scope link
           valid_lft forever preferred_lft forever
  ```

  - There is an eth0 interface which has the pods actual IP address, 198.19.22.132. Notice this matches the IP address that kubectl get pods returned earlier.
```
# ip -c link show up
  1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
  3: eth0@if9: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1410 qdisc noqueue state UP mode DEFAULT group default
      link/ether 3a:0c:14:d0:92:89 brd ff:ff:ff:ff:ff:ff link-netnsid 0
  
```
- eth0 is a link to the host network namespace (indicated by link-netnsid 0). This is the pod's side of the virtual ethernet pair (veth pair) that connects the pod to the node’s host network namespace.

- The @if9 at the end of the interface name (on eth0) is the interface number for the other end of the veth pair, which is located within the host's network namespace itself.  In this example, interface number 9. Remember this number for later. You might want to write it down, because we will need to know this number when we take a look at the other end of the veth pair shortly.

### Routes
```
# ip route
default via 169.254.1.1 dev eth0
169.254.1.1 dev eth0  scope link 
```

This shows that the pod's default route is out over the eth0 interface. i.e. Anytime it wants to send traffic to anywhere other than itself, it will send the traffic over eth0. (Note that the next hop address of 169.254.1.1 is a dummy address used by Calico. Every Calico networked pod sees this as its next hop.)


### How Hosts See Connections to Pods
- SSH into the host.
  
Interfaces- Hosts
```
# ip -c link show up

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 00:15:5d:60:a5:a3 brd ff:ff:ff:ff:ff:ff
5: cali1eaab2bfc77@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1410 qdisc noqueue state UP mode DEFAULT group default
    link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff link-netns cni-8174e7bb-f2a6-0b61-1282-2c425f949ab5
6: cali9c9ee09e807@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1410 qdisc noqueue state UP mode DEFAULT group default
    link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff link-netns cni-e269d0db-f258-6f12-8f31-064bbb4cf87c
7: calid35188eb0ba@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1410 qdisc noqueue state UP mode DEFAULT group default
    link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff link-netns cni-cebefddd-a569-08c2-29d7-7551967f7cf4
8: calif0a98285df9@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1410 qdisc noqueue state UP mode DEFAULT group default
    link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff link-netns cni-0a89d746-b16d-2299-9e6e-948dd7b2b512
9: caliea2aa288365@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1410 qdisc noqueue state UP mode DEFAULT group default
    link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff link-netns cni-f7159375-bf04-e8d8-85b8-0da49bfd53d0
```

Look for the interface number that we noted when looking at the interfaces inside the pod. In our example it was interface number 9.  Looking at interface 9 in the above output, we see caliea2aa288365 which links to @if3 in network namespace ID 3 (the customer pod's network namespace). You may recall that interface 9 in the pod's network namespace was eth0, so this looks exactly as expected for the veth pair that connects the customer pod to the host network namespace. The interface numbers in your environment may be different but you should be able to follow the same chain of reasoning.

You can also see the host end of the veth pairs to other pods running on this node, all beginning with cali.

### How Hosts Route Pod Traffic

-SSH into the node1

```
# ip route
default via 192.168.44.65 dev eth0 proto dhcp src 192.168.44.75 metric 100
192.168.44.64/28 dev eth0 proto kernel scope link src 192.168.44.75
192.168.44.65 dev eth0 proto dhcp scope link src 192.168.44.75 metric 100
198.19.0.0/20 dev eth0 proto kernel scope link src 198.19.0.2
198.19.21.0/26 via 198.19.0.1 dev eth0 proto bird
198.19.21.64/26 via 198.19.0.3 dev eth0 proto bird
198.19.22.128 dev cali1eaab2bfc77 scope link
blackhole 198.19.22.128/26 proto bird
198.19.22.129 dev cali9c9ee09e807 scope link
198.19.22.130 dev calid35188eb0ba scope link
198.19.22.131 dev calif0a98285df9 scope link
198.19.22.132 dev caliea2aa288365 scope link
```

In this example output, we can see the route to the customer pod's IP (198.19.22.132) is via the caliea2aa288365 interface, the host end of the veth pair for the customer pod. You can see similar routes for each of the IPs of the other pods hosted on this node. It's these routes that tell Linux where to send traffic that is destined to a local pod on the node.

We can also see several routes labeled proto bird. These are routes to pods on other nodes that Calico has learned over BGP.

To understand these better, consider this route in the example output above 198.19.21.64/26 via 198.19.0.3 dev eth0 proto bird . It indicates pods with IP addresses falling within the 198.19.21.64/26 CIDR can be reached 198.19.0.3 (which is node2) through the eth0 network interface (the host's main interface to the rest of the network). You should see similar routes in your output for each node.

Calico uses route aggregation to reduce the number of routes when possible. (e.g. /26 in this example). The /26 corresponds to the default block size that Calico IPAM (IP Address Management) allocates on demand as nodes need pod IP addresses. (If desired, the block size can be configured in Calico IPAM settings.)

You can also see the blackhole 198.19.22.128/26 proto bird route. The 198.19.22.128/26 corresponds to the block of IPs that Calico IPAM allocated on demand for this node. This is the block from which each of the local pods got their IP addresses. The blackhole route tells Linux that if it can't find a more specific route for an individual IP in that block then it should discard the packet (rather than sending it out the default route to the network). You will only see traffic that hits this rule if something is trying to send traffic to a pod IP that doesn't exist, for example sending traffic to a recently deleted pod.

If Calico IPAM runs out of blocks to allocate to nodes, then it will use unused IPs from other nodes' blocks. These will be announced over BGP as more specific routes, so traffic to pods will always find its way to the right host.


## Introduction to Encryption

### Wireguard

- Used to secure data in transit using state-of-the-art encryption with Wireguard.
- Wireguesrd is another kind of Overlay network option, But with added benefit of encryption.
- Calico uses a virtual interface for the Wireguard traffic.
- This encrypts on the sending node, Sends the encrypted data over the network to the other node, where the Wireguard interface decrypts the packet, so it can be forwarded on to the destination pod.
- Calico automates all the configuration and provisioning of Wiregurad for you.
- You can turn on and off with a single configuration setting.

![image](https://github.com/user-attachments/assets/f531478a-9c24-4609-885c-6066c4d4abab)

### Enabling encryption

Calico handles all the configuration of WireGuard for you to provide full mesh encryption across all the nodes in your cluster.  WireGuard is included in the latest Linux kernel versions by default, and if running older Linux versions you can easily load it as a kernel module. (Note that if you have some nodes that don’t have WireGuard support, then traffic to/from those specific nodes will be unencrypted.)

While WireGuard performs well, there is still an overhead associated with encryption. As-such, at the time of this writing: this is an optional feature that is not enabled by default.

Let’s start by enabling encryption:
```
calicoctl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
```
Within a few moments WireGuard encryption will be in place on all the nodes in the cluster.

### Inspecting WireGuard status

Every node that is using WireGuard encryption generates its own public key. You check the node status using calicoctl. If WireGuard is active on the node you will see the public key it is using in the status section. 

```
# calicoctl get node node1 -o yaml

apiVersion: projectcalico.org/v3
kind: Node
metadata:
  annotations:
    projectcalico.org/kube-labels: '{"beta.kubernetes.io/arch":"amd64","beta.kubernetes.io/instance-type":"k3s","beta.kubernetes.io/os":"linux","k3s.io/hostname":"node1","k3s.io/internal-ip":"198.19.0.2","kubernetes.io/arch":"amd64","kubernetes.io/hostname":"node1","kubernetes.io/os":"linux","node.kubernetes.io/instance-type":"k3s"}'
  creationTimestamp: "2020-10-20T23:33:09Z"
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/instance-type: k3s
    beta.kubernetes.io/os: linux
    k3s.io/hostname: node1
    k3s.io/internal-ip: 198.19.0.2
    kubernetes.io/arch: amd64
    kubernetes.io/hostname: node1
    kubernetes.io/os: linux
    node.kubernetes.io/instance-type: k3s
  name: node1
  resourceVersion: "8760"
  uid: 66f16def-8f76-46dc-90e3-491bfc75dc9b
spec:
  bgp:
    ipv4Address: 198.19.0.2/20
    ipv4IPIPTunnelAddr: 198.19.22.128
  orchRefs:
  - nodeName: node1
    orchestrator: k8s
  wireguard:
    interfaceIPv4Address: 198.19.22.131
status:
  podCIDRs:
  - 198.19.17.0/24
  wireguardPublicKey: An4UT4PR9XzGgJ5df452Dw034q1SfXZOI1Dp2ebUUWQ=
```

Now, SSH into the node1
```
# ip addr | grep wireguard

10: wireguard.cali: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1400 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 198.19.22.131/32 brd 198.19.22.131 scope global wireguard.cali
```

### Disabling Encryption

Switching off encryption is as simple as switching it on. Let’s try that now.
```
# calicoctl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":false}}'
```

Within a few moments encryption will be disabled. This can be validated by looking at the node once again and seeing that the wireguard public key has been removed from the specification. 

```
# calicoctl get node node1 -o yaml

apiVersion: projectcalico.org/v3
kind: Node
metadata:
  annotations:
    projectcalico.org/kube-labels: '{"beta.kubernetes.io/arch":"amd64","beta.kubernetes.io/instance-type":"k3s","beta.kubernetes.io/os":"linux","k3s.io/hostname":"node1","k3s.io/internal-ip":"198.19.0.2","kubernetes.io/arch":"amd64","kubernetes.io/hostname":"node1","kubernetes.io/os":"linux","node.kubernetes.io/instance-type":"k3s"}'
  creationTimestamp: "2020-10-20T23:33:09Z"
  labels:
    beta.kubernetes.io/arch: amd64
    beta.kubernetes.io/instance-type: k3s
    beta.kubernetes.io/os: linux
    k3s.io/hostname: node1
    k3s.io/internal-ip: 198.19.0.2
    kubernetes.io/arch: amd64
    kubernetes.io/hostname: node1
    kubernetes.io/os: linux
    node.kubernetes.io/instance-type: k3s
  name: node1
  resourceVersion: "9067"
  uid: 66f16def-8f76-46dc-90e3-491bfc75dc9b
spec:
  bgp:
    ipv4Address: 198.19.0.2/20
    ipv4IPIPTunnelAddr: 198.19.22.128
  orchRefs:
  - nodeName: node1
    orchestrator: k8s
status:
  podCIDRs:
  - 198.19.17.0/24
```

## Introduction to IP Pools

IP Pools are Calico resources which define ranges of addresses that the calico IP address management and IPAM CNI Plugin can use.
THe Range IP addresses are decided by CIDR notations.

- To improve performance and scalability, Calico's IP address management alloactes IPs to nodes in-blocks.
- Blocks are allocated Dynamically to nodes as required.
- If a nodes uses up all the IPs from within the blocks it's been allocated, then additional blocks will be automatically allocated to it.
- The block size parameter is the CIDR network mask length of the blocks.
- By default its 26, which meas a block of 64 IPs.
- Depending on how the cluster is configured, If there's no remaining unallocated IP blocks, then a node can borrow individual unused IPs from another node's block.
- IP Pools are also used to specify the IP address range specific networking behaviors. For example- Whether to use an overlay mode for pods allocated IPs from the pool, Or whether to NAT outgoing connections from the cluster, mapping pod IPs to their correcpsonding node IP, which is required whenever your pod IPs are not routable outside of the pod network.

    - For example, If the pod network is an overlay network. You can also mark a pool as disabled if you dont want it to be used for IP address management.
 
- You can specify a node selector that limits which nodes the IP address management can we used on, which allows you to limit specific nodes to using specific ranges of IP addresses for their pod.

- In addition to node selectirs for IP Pools, calico also supports annotations on namespaces, Or individual pods, as another way of controlling which IP pool a pod will get its address from.

- You can also control which IP pools are used on per node basis using CNI configuration files, though with all the other opstions its rare to do so.

  ![image](https://github.com/user-attachments/assets/e8fc4622-22f4-4558-b9e5-fa6daa0b887e)

## BGP Peering



--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------



# Calico Installation and Lab creation

![image](https://github.com/user-attachments/assets/8d8bc2fc-063b-41dd-aef3-c87ca526476e)

Broadly there are 4 different approaches to install.

**Manifest**:-  
This is the most basic method for installing Calico. The Calico docs include a range of manifests for different environments. If you are an advanced user, you can customize the manifests to give you ultimate flexibility and control over your installation. 

**Operator**:-  
Calico 3.15 introduces the option to install Calico using an open-source operator, created by Tigera. This offers simplification for installing and configuring Calico without needing to customize manifests. Additionally, the operator allows you to have a uniform, self-healing environment. Using the Tigera operator is highly recommended.

**Managed Kubernetes Services**:-    
Support for Calico is included with many of the most popular managed Kubernetes services (e.g. EKS, AKS, GKE, IKS), either enabled by default, or optionally enabled using the cloud provider’s management consoles or command line tools, depending on the specific managed Kubernetes service.

**Kubernetes Distros and Installers**:-   
Many Kubernetes distros and installers include support for installing Calico. (e.g. kops, kubespray, microk8s, etc). Most of these currently use manifest based installs under the covers.

# Calico Lab installation using Operator Method 

**Pre-requisites** - Install [Multipass](https://multipass.run) 

### Quick start - Create Cluster 
If you’re on Linux, Mac, or have access to a Bash shell on Windows you can follow these steps to get up and running quickly:

```
curl https://raw.githubusercontent.com/tigera/ccol1/main/control-init.yaml | multipass launch -n control -m 2048M 20.04 --cloud-init -
curl https://raw.githubusercontent.com/tigera/ccol1/main/node1-init.yaml | multipass launch -n node1 20.04 --cloud-init -
curl https://raw.githubusercontent.com/tigera/ccol1/main/node2-init.yaml | multipass launch -n node2 20.04 --cloud-init -
curl https://raw.githubusercontent.com/tigera/ccol1/main/host1-init.yaml | multipass launch -n host1 20.04 --cloud-init -
```

### Starting the Instances
On some platforms, multipass requires you to start the VMs after they have been launched. We can do this by using the multipass start command.

```multipass start --all```

Throughout the deployments for the labs, the instances will reboot once provisioning is complete. As a result, you may have to wait a minute until the instance has fully provisioned. A quick way to check the current state of the cluster is to use the multipass list command.

```multipass list```

Example output:
```
Name                    State             IPv4             Image
control                 Running           172.17.78.3      Ubuntu 20.04 LTS
host1                   Running           172.17.78.6      Ubuntu 20.04 LTS
node1                   Running           172.17.78.7      Ubuntu 20.04 LTS
node2                   Running           172.17.78.12     Ubuntu 20.04 LTS
```

### Validating the Cluster Environment

To validate the lab has successfully started after all four instances we will enter the host1 shell:  

```multipass shell host1```

Once you reach the command prompt of host1, run kubectl get nodes.

```kubectl get nodes -A```

Example output:
```
NAME      STATUS     ROLES    AGE     VERSION
node1     NotReady   <none>   4m44s   v1.18.10+k3s1
node2     NotReady   <none>   2m48s   v1.18.10+k3s1
control   NotReady   master   6m36s   v1.18.10+k3s1
```

Note the “NotReady” status. This is because we have not yet installed a CNI plugin to provide the networking.

The instance we will be using for the following labs will be host1 unless otherwise specified. Think of host1 as your primary entry point into the kubernetes ecosystem, with the other instances acting as the cluster in the cloud.


## Operator based Calico installation:

If you are not already on host1, you can enter host1 by using the multipass shell command.

```multipass shell host1```

The command below will install the operator onto our lab kubernetes cluster:

```kubectl create -f https://docs.projectcalico.org/archive/v3.21/manifests/tigera-operator.yaml```

### Validating the Operator installation
Following the operator being installed, we will validate that the operator is running:

```kubectl get pods -n tigera-operator```

The output from this command should indicate that the operator pod is running:
```
NAME                               READY   STATUS    RESTARTS   AGE
tigera-operator-64f448dfb9-d2fdq   1/1     Running   0          2m33s
```

### Installing Calico
After the operator is in a Running state, we will configure an Installation kind for Calico, specifying the IP Pool that we would like below.

Note that throughout the course we make use of inline manifests (piping stdin to kubectl) to make it easier for you to follow what each manifest does. In most cases it would be a more normal practice to use a vanilla kubectl command with a manifest file (e.g. kubectl apply -f my-installation.yaml).  We recommend taking a minute to read through and make sure you understand the contents of each manifest we apply in this way throughout the rest of the course to get the most out of each example.
```
cat <<EOF | kubectl apply -f -
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  calicoNetwork:
    containerIPForwarding: Enabled
    ipPools:
    - cidr: 198.19.16.0/21
      natOutgoing: Enabled
      encapsulation: None
EOF
```

## Validating the Calico installation
Following the configuration of the installation resource, Calico will begin deploying onto your cluster. This can be validated by running the following command:

```kubectl get tigerastatus/calico```

The output from the command when the installation is complete is:
```
NAME     AVAILABLE   PROGRESSING   DEGRADED   SINCE
calico   True        False         False      10m
```
We can review the environment now by invoking:

```kubectl get pods -A```

Example output:
```
NAMESPACE         NAME                                      READY   STATUS      RESTARTS   AGE
tigera-operator   tigera-operator-84c5c5d6df-zb49b          1/1     Running     0          5m48s
calico-system     calico-typha-868bb997ff-l22n7             1/1     Running     0          4m6s
calico-system     calico-typha-868bb997ff-fvmws             1/1     Running     0          3m24s
calico-system     calico-typha-868bb997ff-8qt45             1/1     Running     0          3m24s
calico-system     calico-node-r94mp                         1/1     Running     0          4m6s
calico-system     calico-node-w5ptt                         1/1     Running     0          4m6s
calico-system     calico-node-zgrvb                         1/1     Running     0          4m6s
kube-system       helm-install-traefik-t68vd                0/1     Completed   0          35m
kube-system       metrics-server-7566d596c8-pccvz           1/1     Running     2          35m
kube-system       local-path-provisioner-6d59f47c7-gh97b    1/1     Running     2          35m
calico-system     calico-kube-controllers-89cf65556-c7gz7   1/1     Running     3          4m6s
kube-system       coredns-7944c66d8d-f4q6g                  1/1     Running     0          35m
kube-system       svclb-traefik-9bxg2                       2/2     Running     0          32s
kube-system       svclb-traefik-pb72f                       2/2     Running     0          32s
kube-system       svclb-traefik-l6mzn                       2/2     Running     0          32s
kube-system       traefik-758cd5fc85-8hcdx                  1/1     Running     0          32s
```
Reviewing Calico pods
Let's take a look at the Calico pods that have been installed by the operator.

```kubectl get pods -n calico-system```
Example Output:
```
NAME                                       READY   STATUS    RESTARTS   AGE
calico-typha-5d788c654b-56wp9              1/1     Running   0          4h28m
calico-node-2bkv5                          1/1     Running   0          4h28m
calico-kube-controllers-5dcfdbc5f4-vpgx5   1/1     Running   0          4h28m
calico-node-8465h                          1/1     Running   0          4h26m
calico-typha-5d788c654b-wn7gf              1/1     Running   0          4h24m
calico-node-qmq5j                          1/1     Running   0          3h57m
calico-typha-5d788c654b-rd8kl              1/1     Running   0          3h56m
```

From here we can see that there are different pods that are deployed.

**Calico-node**:  
Calico-node runs on every Kubernetes cluster node as a DaemonSet. It is responsible for enforcing network policy, setting up routes on the nodes, plus managing any virtual interfaces for IPIP, VXLAN, or WireGuard.  

**Calico-typha**:  
Typha is as a stateful proxy for the Kubernetes API server. It's used by every calico-node pod to query and watch Kubernetes resources without putting excessive load on the Kubernetes API server.  The Tigera Operator automatically scales the number of Typha instances as the cluster size grows.  

**Calico-kube-controllers**:  
Runs a variety of Calico specific controllers that automate synchronization of resources. For example, when a Kubernetes node is deleted, it tidies up any IP addresses or other Calico resources associated with the node.  

Reviewing Node Health

```kubectl get nodes -A```  

Example output:
```
NAME      STATUS   ROLES    AGE   VERSION
control   Ready    master   37m   v1.18.10+k3s1
node2     Ready    <none>   16m   v1.18.10+k3s1
node1     Ready    <none>   31m   v1.18.10+k3s1
```
Now we can see that our Kubernetes nodes have a status of Ready and are operational. Calico is now installed on your cluster and you may proceed to the next module: Installing the Sample Application.




# Install Sample Application

For this lab, we will be deploying an application called "Yet Another Online Bank" (yaobank). The application will consist of 3 microservices.

Yet Another Online Bank diagram. Customer to Summary to Database connectivity.

Customer (which provides a simple web GUI)
Summary (some middleware business logic)
Database (the persistent datastore for the bank)
All the Kubernetes resources (Deployments, Pods, Services, Service Accounts, etc) for Yaobank will all be created within the yaobank namespace.

### Installing the Sample Application

If you are not already on host1, you can enter host1 by using the multipass shell command.  
```multipass shell host1```

To install yaobank into your kubernetes cluster, apply the following manifest:
```
kubectl apply -f https://raw.githubusercontent.com/tigera/ccol1/main/yaobank.yaml
```

### Verify the Sample Application

Check the Deployment Status
To validate that the application has been deployed into your cluster, we will check the rollout status of each of the microservices.

Check the customer microservice: 

```
kubectl rollout status -n yaobank deployment/customer
```

### Access the Sample Application Web GUI
Now we can browse to the service using the service’s NodePort. The NodePort exists on every node in the cluster. We’ll use the control node, but you get the exact same behavior connecting to any other node in the cluster.  

```curl 198.19.0.1:30180```

The resulting output should contain the following balance information:
```
  <body>
        <h1>Welcome to YAO Bank</h1>
        <h2>Name: Spike Curtis</h2>
        <h2>Balance: 2389.45</h2>
        <p><a href="/logout">Log Out >></a></p>
  </body>
```


