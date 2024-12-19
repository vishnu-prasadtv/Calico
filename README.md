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

- BGP is a standards-based network protocol.
- Its supported by most of the routers. Used to power much of the internet.
- Its used to share and synchronize routing information between routers.
- Using BGP, Calico can share routes with other BGP capable routers in the underlying network.
- Typically used in an On-prem, or Private cloud network, rather than Public cloud network.
- Since each node is able to share its local routes to the underlying network, si pods become first-class citizens on the network, and the need of overlay is avoided.
- In large clusters, sharing individual routes to every single pod in the cluster with the underlying network can put a strain on the underlying routers.

  ![image](https://github.com/user-attachments/assets/5fb9b818-2cb7-41d8-94ea-a945fa6b18e9)

- To avoid the above mentioned strain, Calico performs route aggregation based on the IP pool block sizes.
- Each IP block results in one route, rather than there being individual routes for every pod within the block.
- This reduces the number of routes to a trivial load, for almost any network even with the largest of clusters.
- If desired each router on the underlying network can share the routes it learned from the rest of the network back to the node.

![image](https://github.com/user-attachments/assets/1b5cee76-87e0-4f64-a18f-be132bc57984)

### Scenario

There are two address ranges that Kubernetes is normally configured with that are worth understanding:
- The cluster pod CIDR is the range of IP addresses Kubernetes is expecting to be assigned to pods in the cluster.
- The services CIDR is the range of IP addresses that are used for the Cluster IPs of Kubernetes Sevices (the virtual IP that corresponds to each Kubernetes Service).

This can be checked using:

```
# kubectl cluster-info dump | grep -m 2 -E "service-cidr|cluster-cidr"

"k3s.io/node-args": "[\"server\",\"--flannel-backend\",\"none\",\"--cluster-cidr\",\"198.19.16.0/20\",\"--service-cidr\",\"198.19.32.0/20\",\"--write-kubeconfig-mode\",\"664\",\"--disable-network-policy\"]",
```
The IP Pools that Calico has been configured with, which offer finer grained control of IP address ranges to be used by pods in the cluster.
```
# calicoctl get ippools

NAME                  CIDR             SELECTOR
default-ipv4-ippool   198.19.16.0/21   all()
```

In this cluster Calico has been configured to allocate IP addresses for pods from the 198.19.16.0/21 CIDR (which is a subset of the cluster pod CIDR, 198.19.16.0/20, configured on Kubernetes).

Overall we have the following address ranges:
```
198.19.16.0/20 - Cluster Pod CIDR
198.19.16.0/21- Default IP Pool CIDR
198.19.32.0/20 - Service CIDR
```
Note that these IP address ranges are CIDRs, not subnets. This distinction is a little subtle, but in a strict networking sense subnet implies L2 connectivity within the subnet, but the Kubernetes networking model is oriented around L3 connectivity.


 ### Use case
One use of Calico IP Pools is to distinguish between different ranges of addresses with different routability scopes

You are operating at very large scales then IP addresses are precious. You might want to have a range of IPs that is only routable within the cluster, and another range of IPs that is routable across the whole of your enterprise. Then you could choose which pods should get IPs from which range depending on whether workloads from outside of the cluster need to directly access the pods or not.

### Create externally routable IP Pool

Create a new pool for 198.19.24.0/21 that we want to be externally routable.
```
cat <<EOF | calicoctl apply -f - 
---
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: external-pool
spec:
  cidr: 198.19.24.0/21            <--------- New CIDR
  blockSize: 29
  ipipMode: Never
  natOutgoing: true
  nodeSelector: "!all()"
EOF
```

Check new IP Pools:
```
# calicoctl get ippools
Successfully applied 1 'IPPool' resource(s)
NAME                  CIDR             SELECTOR
default-ipv4-ippool   198.19.16.0/21   all()
external-pool         198.19.24.0/21   !all()         <--------- New 
```

Current ranges:
```
198.19.16.0/20 - Cluster Pod CIDR
198.19.16.0/21 - Default IP Pool CIDR
198.19.24.0/21 - External Pool CIDR        <--------- New
198.19.32.0/20 - Service CIDR
```

### Examine BGP peering status

- Switch to node1:
- Check the status of Calico on the node:

```
# sudo calicoctl node status

Calico process is running.
IPv4 BGP status
+--------------+-------------------+-------+----------+-------------+
| PEER ADDRESS |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+--------------+-------------------+-------+----------+-------------+
| 198.19.0.1   | node-to-node mesh | up    | 04:04:44 | Established |
| 198.19.0.3   | node-to-node mesh | up    | 04:04:48 | Established |
+--------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
- This shows that currently this node is only peering with the other nodes in the cluster and is not peering to any networks outside of the cluster.

- Calico adds routes on each node to the local pods on that node. Note that BGP is not involved in programming the routes to the local pods on the node. Each node only uses BGP to share these local routes with the rest of the network, and to learn routes from the rest of the network which it then adds to the node.

### Add a BGP Peer

```
cat <<EOF | calicoctl apply -f -
---
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: bgppeer-global-host1
spec:
  peerIP: 198.19.15.254
  asNumber: 64512
EOF
```

### Examine the new BGP peering status

- Switch to node1 again:

```
# sudo calicoctl node status

Calico process is running.

IPv4 BGP status
+---------------+-------------------+-------+----------+-------------+
| PEER ADDRESS  |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+---------------+-------------------+-------+----------+-------------+
| 198.19.0.1    | node-to-node mesh | up    | 04:04:45 | Established |
| 198.19.0.3    | node-to-node mesh | up    | 04:04:49 | Established |
| 198.19.15.254 | global            | up    | 04:09:36 | Established |
+---------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
The output shows that Calico is now peered with host1 (198.19.15.254). This means Calico can share routes to and learn routes from host1. (Remember we are using host1 to represent a router in this lab.)

In a real-world on-prem deployment you would typically configure Calico nodes within a rack to peer with the ToRs (Top of Rack) routers, and the ToRs are then connected to the rest of the enterprise or data center network. In this way pods, if desired, can be addressed from anywhere on your network. You could even go as far as giving some pods public IP addresses and have them addressable from the internet if you wanted to.


### Configure a Namespace to use External Routable IP Addresses

Calico supports annotations on both namespaces and pods that can be used to control which IP Pool (or even which IP address) a pod will receive when it is created. In this example we're going to create a namespace to host out an externally routable network.

- Notice the annotation that will determine which IP Pool pods in the namespace will use.
- Apply the namespace:

```
cat <<EOF| kubectl apply -f - 
---
apiVersion: v1
kind: Namespace
metadata:
  annotations:
    cni.projectcalico.org/ipv4pools: '["external-pool"]'
  name: external-ns
EOF

namespace/external-ns created
```

Deploy an NGINX pod

```
# kubectl apply -f https://raw.githubusercontent.com/tigera/ccol1/main/nginx.yaml

deployment.apps/nginx created
networkpolicy.networking.k8s.io/nginx created
```

Access the NGINX pod from outside the cluster

```
# curl 198.19.28.208

<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
...
<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```
This confirms that the NGINX pod is directly routable on the broader network. (In this simplified lab this means host1, but in a real environment this could be across the whole of the enterprise network if desired.)

### Check Calico IPAM allocations statistics

Take a quick look at the IP allocation stats from Calico-IPAM, by running the following command:
```
# calicoctl ipam show

+----------+----------------+-----------+------------+-------------+
| GROUPING |      CIDR      | IPS TOTAL | IPS IN USE |  IPS FREE   |
+----------+----------------+-----------+------------+-------------+
| IP Pool  | 198.19.16.0/21 |      2048 | 18 (1%)    | 2030 (99%)  |
| IP Pool  | 198.19.24.0/21 |      2048 | 1 (0%)     | 2047 (100%) |
+----------+----------------+-----------+------------+-------------+
```

It can be a good idea to periodically check IP allocations statistics to check you have sized your IP pools appropriately, for example if you aren’t confident about the number of pods and whether your original sizing of the pools.


## K8s Service Networking

### Cluster IP Service

- When a pod tried to connect to a Cluster IP, the connection is intercepted by rules kube-proxy has programmed into the kernel.
- These rules select a random backing pod to load balance to, changing the destination IP to be the IP of the chosen backing pod, using DNAT, mapping Destion Network Address Translation.
- The Linux kernel tracks the state of these connections, and automatically reverse the DNAT for any return packets.

![image](https://github.com/user-attachments/assets/ff13f575-2d91-47f5-a716-baf23aff4f78)


### NodePort Service

- The Kube-proxy programming rules into the kernel to map connections to backing pods using NAT.
- In NodePort service, in addition to the destination IP address being changed, the source IP is being changed from the client's Pod IP to the node's IP.
- If kube-proxy did'nt do this, the return packets leaving the backing pod node would go directly to the client, without giving the node that did the NAT a chance to reverse the NAT. As a result, the client would drop the traffic because it would not recognize it as being part of the connection it made to the node port.
- The exception to the above behavior is if the service is configured with "externaTrafficPolicy:local", in which case kube-proxy only load balances to backing pods on the same node, and as a result, can just do DNAT, preserving the client's source IP address.
- This is great for improving understandability of application logs, and makes securing services that exposes externally with network policy a lot simpler.

![image](https://github.com/user-attachments/assets/723a082f-8f16-48d0-ac57-51e2039c38bb)


### LoadBalancer service

- The loadbalancer is typically located at a point in the network where return traffic is gauranteed to be routed via it.
- So this service only has to do DNAT for its loadbalancing.
- It loadbalances the traffic across the nodes, using the corresponding node port of the service.
- Kube-proxy then follows the same processes as it did for the standard NodePort, Nating both the source and destination IPs.
- The return packets the follow the same path back to the client.
- Some loadbalancers also support "externalTrafficPolicy:local"- In this case, they will only load balance to nodes hosting a backing po, and kube-proxy will only load balance to backing pods on the same node, preserving the original client source IP all the way to the backing pod.

![image](https://github.com/user-attachments/assets/3f2fd743-0937-4a27-8185-2fe3cc81307d)


# Introduction to Kube-Proxy

- Kube-proxy uses IPtables and IPVS dataplanes.
- Scales to thousands of services.
- Or use Calico eBPF native service handling.
- IPVS, has more performance benefits compared to kube-proxy and IPtables if you have very high numbers of services.
- Calico EBPF dataplane which has built-in native service handling so you dont need to rum kube-proxy at all. This outperfom kube-proxy on either mode.

## Kube-Proxy Cluster IP Implementation

Scenario:

```
SVC
NAME       TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
database   ClusterIP   198.19.33.51    <none>        2379/TCP       24m
summary    ClusterIP   198.19.36.113   <none>        80/TCP         24m
customer   NodePort    198.19.45.149   <none>        80:30180/TCP   24m

Endpoints
NAME       ENDPOINTS                         AGE
database   198.19.21.69:2379                 25m
summary    198.19.21.1:80,198.19.22.131:80   25m
customer   198.19.22.132:80                  25m

Pods
NAME                        READY   STATUS    RESTARTS   AGE   IP              NODE      NOMINATED NODE   READINESS GATES
database-6c5db58d95-x9s7m   1/1     Running   0          25m   198.19.21.69    node2     <none>           <none>
summary-85c56b76d7-j2kc9    1/1     Running   0          25m   198.19.21.1     control   <none>           <none>
summary-85c56b76d7-smjfn    1/1     Running   0          25m   198.19.22.131   node1     <none>           <none>
customer-574bd6cc75-2blnv   1/1     Running   0          25m   198.19.22.132   node1     <none>           <none>
```
To explore the iptables rules kube-proxy programs into the kernel to implement Cluster IP based services, let's look at the Database service. The Summary pods use this service to connect to the Database pods. Kube-proxy uses DNAT to map the Cluster IP to the chosen backing pod.

![image](https://github.com/user-attachments/assets/64fe3a33-e2ca-42ad-bee9-b43a852f97b1)

```
kubectl get endpoints -n yaobank summary
NAME      ENDPOINTS                         AGE
summary   198.19.21.1:80,198.19.22.131:80   27m
```
The summary service has two endpoints (198.19.21.1 on port 80, and 198.19.22.131 on port 80, in this example output). Starting from the KUBE-SERVICES iptables chain, we will traverse each chain until you get to the rule directing traffic to these endpoint IP addresses.

To explore the iptables rules that kube-proxy has set up on the node1. SSH into node1, (It will have set up similar rules on every other node on the cluster.)

To make it easier to manage large numbers of iptables rules, groups of iptables rules can be grouped together into iptables chains. Kube-proxy puts its top level rules into a KUBE-SERVICES chain.
```
sudo iptables -v --numeric --table nat --list KUBE-SERVICES

Chain KUBE-SERVICES (2 references)
 pkts    bytes target                        prot opt in     out     source               destination
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.36.113        /* yaobank/summary:http cluster IP */ tcp dpt:80
    2   120    KUBE-SVC-OIQIZJVJK6E34BR4     tcp  --  *      *       0.0.0.0/0            198.19.36.113        /* yaobank/summary:http cluster IP */ tcp dpt:80
    0     0    KUBE-MARK-MASQ                udp  --  *      *      !198.19.16.0/20       198.19.32.10         /* kube-system/kube-dns:dns cluster IP */ udp dpt:53
    2   158    KUBE-SVC-TCOU7JCQXEZGVUNU     udp  --  *      *       0.0.0.0/0            198.19.32.10         /* kube-system/kube-dns:dns cluster IP */ udp dpt:53
    7   420    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.32.1          /* default/kubernetes:https cluster IP */ tcp dpt:443
    7   420    KUBE-SVC-NPX46M4PTMTKRN6Y     tcp  --  *      *       0.0.0.0/0            198.19.32.1          /* default/kubernetes:https cluster IP */ tcp dpt:443
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.46.45         /* calico-system/calico-typha:calico-typha cluster IP */ tcp dpt:5473
    0     0    KUBE-SVC-RK657RLKDNVNU64O     tcp  --  *      *       0.0.0.0/0            198.19.46.45         /* calico-system/calico-typha:calico-typha cluster IP */ tcp dpt:5473
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.46.209        /* kube-system/traefik:https cluster IP */ tcp dpt:443
    0     0    KUBE-SVC-IKNZCF5XJQBTG3KZ     tcp  --  *      *       0.0.0.0/0            198.19.46.209        /* kube-system/traefik:https cluster IP */ tcp dpt:443
    0     0    KUBE-FW-IKNZCF5XJQBTG3KZ      tcp  --  *      *       0.0.0.0/0            198.19.0.3           /* kube-system/traefik:https loadbalancer IP */ tcp dpt:443
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.33.51         /* yaobank/database:http cluster IP */ tcp dpt:2379
    0     0    KUBE-SVC-AE2X4VPDA5SRYCA6     tcp  --  *      *       0.0.0.0/0            198.19.33.51         /* yaobank/database:http cluster IP */ tcp dpt:2379
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.45.149        /* yaobank/customer:http cluster IP */ tcp dpt:80
    0     0    KUBE-SVC-PX5FENG4GZJTCELT     tcp  --  *      *       0.0.0.0/0            198.19.45.149        /* yaobank/customer:http cluster IP */ tcp dpt:80
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.32.10         /* kube-system/kube-dns:dns-tcp cluster IP */ tcp dpt:53
    0     0    KUBE-SVC-ERIFXISQEP7F7OF4     tcp  --  *      *       0.0.0.0/0            198.19.32.10         /* kube-system/kube-dns:dns-tcp cluster IP */ tcp dpt:53
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.32.10         /* kube-system/kube-dns:metrics cluster IP */ tcp dpt:9153
    0     0    KUBE-SVC-JD5MR3NA4I4DYORP     tcp  --  *      *       0.0.0.0/0            198.19.32.10         /* kube-system/kube-dns:metrics cluster IP */ tcp dpt:9153
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.38.163        /* kube-system/metrics-server: cluster IP */ tcp dpt:443
    0     0    KUBE-SVC-LC5QY66VUV2HJ6WZ     tcp  --  *      *       0.0.0.0/0            198.19.38.163        /* kube-system/metrics-server: cluster IP */ tcp dpt:443
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.38.41         /* kube-system/traefik-prometheus:metrics cluster IP */ tcp dpt:9100
    0     0    KUBE-SVC-W3ST5H65YH2QID6S     tcp  --  *      *       0.0.0.0/0            198.19.38.41         /* kube-system/traefik-prometheus:metrics cluster IP */ tcp dpt:9100
    0     0    KUBE-MARK-MASQ                tcp  --  *      *      !198.19.16.0/20       198.19.46.209        /* kube-system/traefik:http cluster IP */ tcp dpt:80
    0     0    KUBE-SVC-X3WUOHPTYIG7AA3Q     tcp  --  *      *       0.0.0.0/0            198.19.46.209        /* kube-system/traefik:http cluster IP */ tcp dpt:80
    0     0    KUBE-FW-X3WUOHPTYIG7AA3Q      tcp  --  *      *       0.0.0.0/0            198.19.0.3           /* kube-system/traefik:http loadbalancer IP */ tcp dpt:80
  931 55938    KUBE-NODEPORTS                all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service nodeports; NOTE: this must be the last rule in this chain */ ADDRTYPE match dst-type LOCAL
```

Each iptables chain consists of a list of rules that are executed in order until a rule matches. The key columns/elements to note in this output are:

target - which chain iptables will jump to if the rule matches
prot - the protocol match criteria
source, and destination - the source and destination IP address match criteria
the comments that kube-proxy includes
the additional match criteria at the end of each rule - e.g dpt:80 that specifies the destination port match
You can see this chain includes rules to jump to service specific chains, one for each service.


### KUBE-SERVICES -> KUBE-SVC-XXXXXXXXXXXXXXXX

The rules for the summary service.
```
sudo iptables -v --numeric --table nat --list KUBE-SERVICES | grep -E summary

 0     0 KUBE-MARK-MASQ             tcp  --  *      *      !198.19.16.0/20       198.19.36.113        /* yaobank/summary:http cluster IP */ tcp dpt:80
 2   120 KUBE-SVC-OIQIZJVJK6E34BR4  tcp  --  *      *       0.0.0.0/0            198.19.36.113        /* yaobank/summary:http cluster IP */ tcp dpt:80

```
The second rule directs traffic destined for the summary service clusterIP (198.19.36.113 in the example output) to the chain that load balances the service (KUBE-SVC-XXXXXXXXXXXXXXXX).


### KUBE-SVC-XXXXXXXXXXXXXXXX -> KUBE-SEP-XXXXXXXXXXXXXXXX

kube-proxy in iptables mode uses a randomized equal cost selection algorithm to load balance traffic between pods. We currently have two summary pods, so it should have rules in place that load balance equally across both pods.

Let's examine how this load balancing works using the chain name returned from our previous command. (Remember your chain name may be different than this example.)

```
sudo iptables -v --numeric --table nat --list KUBE-SVC-OIQIZJVJK6E34BR4

Chain KUBE-SVC-OIQIZJVJK6E34BR4 (1 references)
 pkts   bytes    target                     prot opt in     out     source               destination
    2   120      KUBE-SEP-Q6MJJR7VDMWJNZBE  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* yaobank/summary:http */ statistic mode random probability 0.50000000000
    0     0      KUBE-SEP-MR2OHPODPKVEKHD4  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* yaobank/summary:http */
```

Notice that kube-proxy is using the iptables statistic module to set the probability for a packet to be randomly matched.

The first rule directs traffic destined for the summary service to a chain that delivers packets to the first service endpoint (KUBE-SEP-Q6MJJR7VDMWJNZBE) with a probability of 0.50000000000. The second rule unconditionally directs to the second service endpoint chain (KUBE-SEP-MR2OHPODPKVEKHD4). The result is that traffic is load balanced across the service endpoints equally (on average).

If there were 3 service endpoints then the first chain matches would be probability 0.33333333, the second probability 0.5, and the last unconditional. The result of this is that each service endpoint receives a third of the traffic (on average).

And so on for any number of services!

### KUBE-SEP-XXXXXXXXXXXXXXXX -> summary pod

```
sudo iptables -v --numeric --table nat --list KUBE-SEP-MR2OHPODPKVEKHD4

Chain KUBE-SEP-MR2OHPODPKVEKHD4 (1 references)
 pkts bytes target           prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ   all  --  *      *       198.19.22.131        0.0.0.0/0            /* yaobank/summary:http */
    0     0 DNAT             tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* yaobank/summary:http */ tcp to:198.19.22.131:80
```
The second rule performs the DNAT that changes the destination IP from the service's clusterIP to the IP address of the service endpoint backing pod (198.19.22.131 in this example). After this, standard Linux routing can handle forwarding the packet like it would any other packet.


Recap
You've just traced the kube-proxy iptables rules used to load balance traffic to summary pods exposed as a service of type ClusterIP.

In summary, for a packet being sent to a clusterIP:   -------------->>>>>>>>>>>
1. The KUBE-SERVICES chain matches on the clusterIP and jumps to the corresponding KUBE-SVC-XXXXXXXXXXXXXXXX chain.
2. The KUBE-SVC-XXXXXXXXXXXXXXXX chain load balances the packet to a random service endpoint KUBE-SEP-XXXXXXXXXXXXXXXX chain.
3. The KUBE-SEP-XXXXXXXXXXXXXXXX chain DNATs the packet so it will get routed to the service endpoint (backing pod).



## Kube-Proxy NodePort Implementation

To explore the iptables rules kube-proxy programs into the kernel to implement Node Port based services, let's look at the Customer service. External clients use this service to connect to the Customer pods.  Kube-proxy uses NAT to map the Node Port to the chosen backing pod, and the source IP to the node IP of the ingress node, so that it can reverse the NAT for return packets.  (If it didn't change the source IP then return packets would go directly back to the client, without the node that did the NAT having a chance to reverse the NAT, and as a result the client would not recognize the packets as being part of the connection it made to the Node Port).

![image](https://github.com/user-attachments/assets/c0f7374f-a92e-45a3-bcf8-1b0fcada4a14)


Service endpoints for customer NodePort service.
```
EP
# kubectl get endpoints -n yaobank customer
NAME       ENDPOINTS          AGE
customer   198.19.22.132:80   39m

```
The customer service has one endpoint (198.19.22.132 on port 80 in this example output). Starting from the KUBE-SERVICES iptables chain, we will traverse each chain until you get to the rule directing traffic to this endpoint IP address.

###  KUBE-SERVICES -> KUBE-NODEPORTS

Node1

The KUBE-SERVICE chain handles the matching for service types ClusterIP and LoadBalancer. At the end of KUBE-SERVICE chain, another custom chain KUBE-NODEPORTS will handle traffic for service type NodePort.
```
# sudo iptables -v --numeric --table nat --list KUBE-SERVICES | grep KUBE-NODEPORTS

1216 73038 KUBE-NODEPORTS  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kubernetes service nodeports; NOTE: this must be the last rule in this chain */ ADDRTYPE match dst-type LOCAL
```
“match dst-type LOCAL” matches any packet with a local host IP as the destination. I.e. any address that is assigned to one of the host's interfaces.

### KUBE-NODEPORTS -> KUBE-SVC-XXXXXXXXXXXXXXXX

```
# sudo iptables -v --numeric --table nat --list KUBE-NODEPORTS

Chain KUBE-NODEPORTS (1 references)
 pkts bytes target                      prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/traefik:https */ tcp dpt:31397
    0     0 KUBE-SVC-IKNZCF5XJQBTG3KZ   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/traefik:https */ tcp dpt:31397
    0     0 KUBE-MARK-MASQ              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* yaobank/customer:http */ tcp dpt:30180
    0     0 KUBE-SVC-PX5FENG4GZJTCELT   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* yaobank/customer:http */ tcp dpt:30180
    0     0 KUBE-MARK-MASQ              tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/traefik:http */ tcp dpt:32196
    0     0 KUBE-SVC-X3WUOHPTYIG7AA3Q   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* kube-system/traefik:http */ tcp dpt:32196
```

The fourth rule directs traffic destined for the customer service to the chain that load balances the service (KUBE-SVC-PX5FENG4GZJTCELT). tcp dpt:30180 matches any packet with the destination port of tcp 30180 (the node port of the customer service).

### KUBE-SVC-XXXXXXXXXXXXXXXX -> KUBE-SEP-XXXXXXXXXXXXXXXX
```
sudo iptables -v --numeric --table nat --list KUBE-SVC-PX5FENG4GZJTCELT

Chain KUBE-SVC-PX5FENG4GZJTCELT (2 references)
    pkts bytes target                     prot opt in     out     source               destination
    0     0    KUBE-SEP-UBXKSM3V2OSEF4IL  all  --  *      *       0.0.0.0/0            0.0.0.0/0            /* yaobank/customer:http */
```
As we only have a single backing pod for the customer service, there is no load balancing to do, so there is a single rule that directs all traffic to the chain that delivers the packet to the service endpoint (KUBE-SEP-UBXKSM3V2OSEF4IL).


### KUBE-SEP-XXXXXXXXXXXXXXXX -> customer endpoint
```
# sudo iptables -v --numeric --table nat --list KUBE-SEP-UBXKSM3V2OSEF4IL

Chain KUBE-SEP-UBXKSM3V2OSEF4IL (1 references)
 pkts bytes target          prot opt in     out     source               destination
    0     0 KUBE-MARK-MASQ  all  --  *      *       198.19.22.132        0.0.0.0/0            /* yaobank/customer:http */
    0     0 DNAT            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            /* yaobank/customer:http */ tcp to:198.19.22.132:80
```
This rule delivers the packet to the customer service endpoint.

The second rule performs the DNAT that changes the destination IP from the service's clusterIP to the IP address of the service endpoint backing pod (198.19.22.132 in this example). After this, standard Linux routing can handle forwarding the packet like it would any other packet.


Recap
You've just traced the kube-proxy iptables rules used to load balance traffic to customer pods exposed as a service of type NodePort.

In summary, for a packet being sent to a NodePort:

The end of the KUBE-SERVICES chain jumps to the KUBE-NODEPORTS chain

1. The KUBE-NODEPORTS chain matches on the NodePort and jumps to the corresponding KUBE-SVC-XXXXXXXXXXXXXXXX chain.
2. The KUBE-SVC-XXXXXXXXXXXXXXXX chain load balances the packet to a random service endpoint KUBE-SEP-XXXXXXXXXXXXXXXX chain.
3. The KUBE-SEP-XXXXXXXXXXXXXXXX chain DNATs the packet so it will get routed to the service endpoint (backing pod).

## Calico Native Service Handling

- As an alternative to using kube-proxy, Calico's eBPF data plane supports native service handling.
- This presetves source IP to simplify network policy, and offers DSR (Direct Server Return) to reduce the number of network hops for return traffic.
- It even provides loadbalancing independent of topology, with reduced CPU and latency compared to kube-proxy.
- When an incoming connection is received from an external client, Calico's native service handling is able to load balance the connection, forwarding the packets to another node if required, without any NAT.
- The receiving node then performs DNAT, to map the packets to the chosen backing pod.
- Reverse packest get the DNAT reversed, and then if DSR is enabled, return directly to the client.

![image](https://github.com/user-attachments/assets/d37affa0-2f37-4884-b6e9-e75403eae4ce)

Calico's eBPF dataplane is an alternative to the default standard Linux dataplane (which is iptables based). The eBPF dataplane has a number of advantages:

- It scales to higher throughput.
- It uses less CPU per GBit.
- It has native support for Kubernetes services (without needing kube-proxy) that:
   - Reduces first packet latency for packets to services.
   - Preserves external client source IP addresses all the way to the pod.
   - Supports DSR (Direct Server Return) for more efficient service routing.
   - Uses less CPU than kube-proxy to keep the dataplane in sync.

The eBPF dataplane also has some limitations, which are described in the Enable the eBPF dataplane guide in the Calico documentation.

### Scenarios

###NodePort without source IP preservation

Before we enable Calico’s eBPF based native service handling, let’s take a closer look at how kube-proxy handles node ports, and show that the client source IP is not preserved all the way to the pod backing the service. Kube-proxy uses NAT to map the destination IP to the chosen backing pod (DNAT), and map the source IP to the node IP of the ingress node (SNAT).  It does the SNAT so that standard Linux networking routes the return packets back to the ingress node so it can reverse the NAT.

![image](https://github.com/user-attachments/assets/96ab5a75-553f-460d-a29d-1680eefa5d96)

From host1

```
# curl 198.19.0.1:30180

Logs in customer pod:

198.19.0.1 - - [20/Oct/2020 23:58:06] "GET / HTTP/1.1" 200 -
198.19.0.1 - - [21/Oct/2020 00:03:08] "GET / HTTP/1.1" 200 -
198.19.0.1 - - [21/Oct/2020 00:11:31] "GET / HTTP/1.1" 200 -
198.19.0.1 - - [21/Oct/2020 00:30:09] "GET / HTTP/1.1" 200 -
```

Note that the source IP that the pod sees is 198.19.0.1, which is the control node, the node we accessed the node port via. When traffic arrives from outside the cluster, kube-proxy applies SNAT to the traffic on the ingress node; from the pod's point of view, this makes the traffic appear to come from the ingress node (198.19.0.1 in this case). The SNAT is required to make sure the return traffic flows back through the same node so that NodePort DNAT can be undone.

Note that if the cluster was configured to use an overlay (VXLAN or IPIP) or wireguard, then the SNAT would make the traffic appear to come from the IP address associated with the corresponding virtual interface on the ingress node.


### Enable Calico eBPF

To enable Calico eBPF we need to:

- Configure Calico so it knows how to connect directly to the API server (rather than relying on kube-proxy to help it connect)
- Disable kube-proxy
- Configure Calico to switch to the eBPF dataplane

### Configure Calico to connect directly to the API server

In eBPF mode, Calico replaces kube-proxy. This means that Calico needs to be able to connect directly to the API server (just as kube-proxy would normally do). Calico supports a ConfigMap to configure these direct connections for all of its components.

Note: It is important the ConfigMap points at a stable address for the API server(s) in your cluster. If you have a HA cluster, the ConfigMap should point at the load balancer in front of your API servers so that Calico will be able to connect even if one control plane node goes down. In clusters that use DNS load balancing to reach the API server (such as kops and EKS clusters) you should configure Calico to talk to the corresponding domain name.

In our case, we have a single control node hosting the Kubernetes API service. So we will just configure the control node IP address directly.

```
cat <<EOF | kubectl apply -f -
---
kind: ConfigMap
apiVersion: v1
metadata:
  name: kubernetes-services-endpoint
  namespace: tigera-operator
data:
  KUBERNETES_SERVICE_HOST: "198.19.0.1"
  KUBERNETES_SERVICE_PORT: "6443"
EOF

configmap/kubernetes-services-endpoint created
```

ConfigMaps can take up to 60s to propagate; wait for 60s and then restart the operator, which itself also depends on this config:
```
# kubectl delete pod -n tigera-operator -l k8s-app=tigera-operator
# watch kubectl get pods -n calico-system
```

### Disable kube-proxy

Calico’s eBPF native service handling replaces kube-proxy. You can free up resources from your cluster by disabling and no longer running kube-proxy. When Calico is switched into eBPF mode it will try to clean up kube-proxy's iptables rules if they are present. 

Kube-proxy normally runs as a daemonset. So an easy way to stop and remove kube-proxy from every node is to add a nodeSelector to that daemonset which excludes all nodes.

In some environments, kube-proxy is installed/run via a different mechanism. For example, a k3s cluster typically doesn’t have a kube-proxy daemonset, and instead is controlled by install time k3s configuration.  In this case, you would still want to get rid of kube-proxy, but if you just wanted to try out Calico eBPF quickly on such a cluster, you can tell Calico to not try to tidy up kube-proxy’s iptables rules, and instead allow them to co-exist.  (Calico eBPF will still bypass the iptable rules, so they have no effect on the traffic.)

Let’s do that now in this cluster by running this command on host1:
```
# calicoctl patch felixconfiguration default --patch='{"spec": {"bpfKubeProxyIptablesCleanupEnabled": false}}'
```
###  Switch on eBPF mode

You're now ready to switch on eBPF mode. To do so, on host1, use calicoctl to enable the eBPF mode flag:
```
# kubectl patch installation.operator.tigera.io default --type merge -p '{"spec":{"calicoNetwork":{"linuxDataplane":"BPF", "hostPorts":null}}}'
```
Since enabling eBPF mode can disrupt existing connections, restart YAO Bank's customer and summary pods:
```
kubectl delete pod -n yaobank -l app=customer
kubectl delete pod -n yaobank -l app=summary
```

### Source IP preservation
Now that we've switched to the Calico eBPF data plane, Calico native service handling handles the service without needing kube-proxy. As it is handling the packets with eBPF, rather than the standard Linux networking pipeline, it is able to special case this traffic in a way that allows it to preserve the source IP address, including special handling of return traffic so it still is returned from the original ingress node.

![image](https://github.com/user-attachments/assets/a4209afb-c81f-4976-9024-db5be8efefbe)

So we can see the effect of source IP preservation, tail the logs of YAO Bank's customer pod again in your second shell window:
```
node1
curl 198.19.0.1:30180

You should see these logs from the customer pod appear:

198.19.15.254 - - [05/Oct/2020 10:04:37] "GET / HTTP/1.1" 200 -
198.19.15.254 - - [05/Oct/2020 10:04:41] "GET /logout HTTP/1.1" 404 -
198.19.15.254 - - [05/Oct/2020 10:04:45] "GET / HTTP/1.1" 200 -
```
This time the source IP that the pod sees is 198.19.15.254, which is host1, which was the real source of the request, showing that the source IP has been preserved end-to-end.

## Direct Server Return (DSR)

Calico’s eBPF dataplane also supports DSR (Direct Server Return). DSR allows the node hosting a service backing pod to send return traffic directly to the external client rather than taking the extra hop back via the ingress node (the control node in our example). 

![image](https://github.com/user-attachments/assets/7a6ca8e0-c9c3-48ad-a661-eddd733c1381)

DSR requires a network fabric with suitably relaxed RPF (reverse path filtering) enforcement. In particular the network must accept packets from nodes that have a source IP of another node.  In addition, any load balancing or NAT that is done outside the cluster must be able to handle the DSR response packets from all nodes.

### Snoop traffic without DSR

To show the effect of this, let’s snoop the traffic on the control node.

- SSH into the control node:
- Snoop the traffic associated with the node port:

```
sudo tcpdump -nvi any 'tcp port 30180'
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
```

While the above command is running, access YAO Bank from your other host1 shell, using the node port via the control node:
```
curl 198.19.0.1:30180
```

The traffic will get logged by the tcpdump, for example:
```
    13:59:32.826328 IP (tos 0x0, ttl 64, id 59453, offset 0, flags [DF], proto TCP (6), length 60)
    198.19.15.254.57064 > 198.19.0.1.30180: Flags [S], cksum 0x520e (correct), seq 2716257334, win 64240, options [mss 1460,sackOK,TS val 3319780880 ecr 0,nop,wscale 7], length 0
13:59:32.827552 IP (tos 0x0, ttl 62, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    198.19.0.1.30180 > 198.19.15.254.57064: Flags [S.], cksum 0x287a (correct), seq 23038493, ack 2716257335, win 65184, options [mss 1370,sackOK,TS val 2052464730 ecr 3319780880,nop,wscale 7], length 0
13:59:32.828602 IP (tos 0x0, ttl 64, id 59454, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.57064 > 198.19.0.1.30180: Flags [.], cksum 0x5394 (correct), ack 1, win 502, options [nop,nop,TS val 3319780883 ecr 2052464730], length 0
13:59:32.828602 IP (tos 0x0, ttl 64, id 59455, offset 0, flags [DF], proto TCP (6), length 132)
    198.19.15.254.57064 > 198.19.0.1.30180: Flags [P.], cksum 0xa09d (correct), seq 1:81, ack 1, win 502, options [nop,nop,TS val 3319780883 ecr 2052464730], length 80
13:59:32.829986 IP (tos 0x0, ttl 62, id 33835, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.0.1.30180 > 198.19.15.254.57064: Flags [.], cksum 0x533b (correct), ack 81, win 509, options [nop,nop,TS val 2052464732 ecr 3319780883], length 0
13:59:32.853492 IP (tos 0x0, ttl 62, id 33836, offset 0, flags [DF], proto TCP (6), length 69)
    198.19.0.1.30180 > 198.19.15.254.57064: Flags [P.], cksum 0x9345 (correct), seq 1:18, ack 81, win 509, options [nop,nop,TS val 2052464756 ecr 3319780883], length 17
13:59:32.853517 IP (tos 0x0, ttl 62, id 33837, offset 0, flags [DF], proto TCP (6), length 784)
    198.19.0.1.30180 > 198.19.15.254.57064: Flags [FP.], cksum 0x037f (correct), seq 18:750, ack 81, win 509, options [nop,nop,TS val 2052464756 ecr 3319780883], length 732
13:59:32.855113 IP (tos 0x0, ttl 64, id 59456, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.57064 > 198.19.0.1.30180: Flags [.], cksum 0x52ff (correct), ack 18, win 502, options [nop,nop,TS val 3319780909 ecr 2052464756], length 0
13:59:32.855323 IP (tos 0x0, ttl 64, id 59457, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.57064 > 198.19.0.1.30180: Flags [.], cksum 0x5023 (correct), ack 751, win 501, options [nop,nop,TS val 3319780909 ecr 2052464756], length 0
13:59:32.857380 IP (tos 0x0, ttl 64, id 59458, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.57064 > 198.19.0.1.30180: Flags [F.], cksum 0x5021 (correct), seq 81, ack 751, win 501, options [nop,nop,TS val 3319780910 ecr 2052464756], length 0
13:59:32.860678 IP (tos 0x0, ttl 62, id 0, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.0.1.30180 > 198.19.15.254.57064: Flags [.], cksum 0x5012 (correct), ack 82, win 509, options [nop,nop,TS val 2052464763 ecr 3319780910], length 0
```

You can see there is traffic flowing via the node port in both directions. In this example:

= Traffic from host1 to the node port: 198.19.15.254.57064 > 198.19.0.1.30180 
- Traffic from the node port to host1: 198.19.0.1.30180 > 198.19.15.254.57064 
Leave the tcpdump command running and we’ll see what difference turning on DSR makes.

### Switch on DSR

Run the following command from host1 to turn on DSR:
```
# calicoctl patch felixconfiguration default --patch='{"spec": {"bpfExternalServiceMode": "DSR"}}'
```
Now access YAO Bank from host1 using the node port via the control node:
```
curl 198.19.0.1:30180
```

The traffic will get logged by the tcpdump, for example:
```
    198.19.15.254.56898 > 198.19.0.1.30180: Flags [S], cksum 0xf4ce (correct), seq 3085566351, win 64240, options [mss 1460,sackOK,TS val 3319654555 ecr 0,nop,wscale 7], length 0
13:57:26.502803 IP (tos 0x0, ttl 64, id 29496, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.56898 > 198.19.0.1.30180: Flags [.], cksum 0xfa75 (correct), ack 3427182734, win 502, options [nop,nop,TS val 3319654556 ecr 2052338405], length 0
13:57:26.503215 IP (tos 0x0, ttl 64, id 29497, offset 0, flags [DF], proto TCP (6), length 132)
    198.19.15.254.56898 > 198.19.0.1.30180: Flags [P.], cksum 0x477e (correct), seq 0:80, ack 1, win 502, options [nop,nop,TS val 3319654557 ecr 2052338405], length 80
13:57:31.558591 IP (tos 0x0, ttl 64, id 29498, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.56898 > 198.19.0.1.30180: Flags [.], cksum 0xd293 (correct), ack 18, win 502, options [nop,nop,TS val 3319659613 ecr 2052343461], length 0
13:57:31.558592 IP (tos 0x0, ttl 64, id 29499, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.56898 > 198.19.0.1.30180: Flags [.], cksum 0xcfb7 (correct), ack 751, win 501, options [nop,nop,TS val 3319659613 ecr 2052343461], length 0
13:57:31.559193 IP (tos 0x0, ttl 64, id 29500, offset 0, flags [DF], proto TCP (6), length 52)
    198.19.15.254.56898 > 198.19.0.1.30180: Flags [F.], cksum 0xcfb6 (correct), seq 80, ack 751, win 501, options [nop,nop,TS val 3319659613 ecr 2052343461], length 0
```
You should only see traffic in one direction, from host1 to the node port on the control node. The return traffic is going directly back to the client (host1) from the node hosting the customer pod backing the service (node1).

## Introduction to Advertising Services

- One alternative to using node ports, or load balancers, is to advertise service IP addresses over BGP.
- This reuires the cluster to be running on an underlying network that supports BGP, which typically means an onprem or private cloud deployment, with standard top of rack routers.

![image](https://github.com/user-attachments/assets/5d8aceec-8d4c-4fa3-9f6c-c2f7433e60e0)

- Conceptually, removing the need for an external load balancer, and instead making the whole of your network service aware, and using your network routers to do the load balancing.
- When used in conjunction with Calico eBPF native service handling, this provides even load balancing that's independent of the topology of your network and preserves client source IP addresses all the way to the backing pod.

![image](https://github.com/user-attachments/assets/fe3307e8-94b0-4418-98ea-15bc8685083f)

###  Advertise Cluster IP Range

Advertising services over BGP allows you to directly access the service without using NodePorts or a cluster Ingress Controller.

Examine routes

Host1
```
ip route

default via 192.168.159.113 dev eth0 proto dhcp src 192.168.159.121 metric 100
192.168.159.112/28 dev eth0 proto kernel scope link src 192.168.159.121
192.168.159.113 dev eth0 proto dhcp scope link src 192.168.159.121 metric 100
198.19.0.0/20 dev eth0 proto kernel scope link src 198.19.15.254
198.19.28.208/29 via 198.19.0.2 dev eth0 proto bird
```

- You can see one route that was learned from Calico that provides access to the nginx pod that was created in the externally routable namespace (the route ending in “proto bird”, the last line in this example output). In this lab we will advertise Kubernetes services (rather than individual pods) over BGP.

### Update Calico BGP configuration

The serviceClusterIPs clause below tells Calico to advertise the cluster IP range.

Apply the configuration:
```
cat <<EOF | calicoctl apply -f -
---
apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  name: default
spec:
  serviceClusterIPs:
  - cidr: "198.19.32.0/20"
EOF
```
Verify the BGPConfiguration update worked and contains the serviceClusterIPs key:
```
# calicoctl get bgpconfig default -o yaml

apiVersion: projectcalico.org/v3
kind: BGPConfiguration
metadata:
  creationTimestamp: "2020-10-19T21:16:09Z"
  name: default
  resourceVersion: "30335"
  uid: 2bd1a883-4425-4274-a8ce-fe706de98e6a
spec:
  serviceClusterIPs:
  - cidr: 198.19.32.0/20
```

Examine routes
```
ip route

default via 192.168.159.113 dev eth0 proto dhcp src 192.168.159.117 metric 100
192.168.159.112/28 dev eth0 proto kernel scope link src 192.168.159.117
192.168.159.113 dev eth0 proto dhcp scope link src 192.168.159.117 metric 100
198.19.0.0/20 dev eth0 proto kernel scope link src 198.19.15.254
198.19.28.208/29 via 198.19.0.2 dev eth0 proto bird
198.19.32.0/20 proto bird
        nexthop via 198.19.0.1 dev eth0 weight 1
        nexthop via 198.19.0.2 dev eth0 weight 1
        nexthop via 198.19.0.3 dev eth0 weight 1

```

You should now see the cluster service cidr 198.19.32.0/20 advertised from each of the kubernetes cluster nodes. This means that traffic to any service's cluster IP address will get load balanced across all nodes in the cluster by the network using ECMP (Equal Cost Multi Path). Kube-proxy or Calico native service handling then load balances the cluster IP across the service endpoints (backing pods) in exactly the same way as if a pod had accessed a service via a cluster IP.

Verify we can access cluster IPs
```
kubectl get svc -n yaobank customer

NAME       TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
customer   NodePort   198.19.35.118   <none>        80:30180/TCP   33m

```

Confirm we can access it from host1:
```
curl 198.19.35.118
```

Advertising Cluster IPs in this way provides an alternative to accessing services via Node Ports (simplifying client service discovery without clients needing to understand DNS SRV records) or external network load balancers (reducing overall equipment costs).  

### Advertise External IPs

If you want to advertise a service using an IP address outside of the service cluster IP range, you can configure the service to have one or more external-IPs.

Examine the existing services
```
kubectl get svc -n yaobank

NAME       TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
database   ClusterIP   198.19.45.32    <none>        2379/TCP       4m2s
summary    ClusterIP   198.19.38.28    <none>        80/TCP         4m2s
customer   NodePort    198.19.35.118   <none>        80:30180/TCP   4m1s
```
Note that none of them currently have an EXTERNAL-IP.

### Update BGP configuration

Update the Calico BGP configuration to advertise a service external IP CIDR range of 198.19.48.0/20:
```
calicoctl patch BGPConfig default --patch \
   '{"spec": {"serviceExternalIPs": [{"cidr": "198.19.48.0/20"}]}}'
```
Note that serviceExternalIPs is a list of CIDRs, so you could for example add individual /32 IP addresses if there were just a small number of specific IPs you wanted to advertise.

Examine routes on host1:

```
ip route

default via 192.168.159.113 dev eth0 proto dhcp src 192.168.159.117 metric 100
192.168.159.112/28 dev eth0 proto kernel scope link src 192.168.159.117
192.168.159.113 dev eth0 proto dhcp scope link src 192.168.159.117 metric 100
198.19.0.0/20 dev eth0 proto kernel scope link src 198.19.15.254
198.19.28.208/29 via 198.19.0.2 dev eth0 proto bird
198.19.32.0/20 proto bird
        nexthop via 198.19.0.1 dev eth0 weight 1
        nexthop via 198.19.0.2 dev eth0 weight 1
        nexthop via 198.19.0.3 dev eth0 weight 1
198.19.38.11 via 198.19.0.2 dev eth0 proto bird
198.19.48.0/20 proto bird
        nexthop via 198.19.0.1 dev eth0 weight 1
        nexthop via 198.19.0.2 dev eth0 weight 1
        nexthop via 198.19.0.3 dev eth0 weight 1
```

You should now have a route for the external ID CIDR (198.19.48.0/20) with next hops to each of our cluster nodes.

###   Assign the service external IP

Assign the service external IP 198.19.48.10/20 to the customer service.

```
kubectl patch svc -n yaobank customer -p  '{"spec": {"externalIPs": ["198.19.48.10"]}}'
```

Examine the services again to validate everything is as expected:
```
kubectl get svc -n yaobank

NAME       TYPE        CLUSTER-IP      EXTERNAL-IP    PORT(S)        AGE
database   ClusterIP   198.19.42.125   <none>         2379/TCP       32m
summary    ClusterIP   198.19.32.103   <none>         80/TCP         32m
customer   NodePort    198.19.38.11    198.19.48.10   80:30180/TCP   32m
```

You should now see the external ip (198.19.48.10) assigned to the customer service. We can now access the customer service from outside the cluster using the external ip address (198.19.48.10) we just assigned.

Verify we can access the service's external IP- Connect to the customer service from the standalone node using the service external IP 198.19.48.10:
```
curl 198.19.48.10
```
As you can see the service has been made available outside of the cluster via bgp routing and network load balancing.


We've covered five different ways for connecting to your pods from outside the cluster during this Module.

- Via a standard NodePort on a specific node. (This is how you connected to the YAO Bank web front end when you first deployed it.)
- Direct to the pod IP address by using externally routable IP Pools.
- Advertising the service cluster IP range. (And using ECMP to load balance across all nodes in the cluster.)
- Advertising individual cluster IPs. (Services with externalTrafficPolicy: Local, using ECMP to load balance only to the nodes hosting the pods backing the service.)
- Advertising service external-IPs. (So you can use service IP addresses outside of the cluster IP range.)

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


