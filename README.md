# Calico Lab installation

**Pre-requisites** - Install [Multipass](https://multipass.run) 

![image](https://github.com/user-attachments/assets/8d8bc2fc-063b-41dd-aef3-c87ca526476e)


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


# Calico in Kubernetes -

*Kubernetes Network Model:*

Core Principles
1.  Every pod gets its own IP address.
2.  Containers within the pod can share that IP address and communicate freely with each other.
3.  Pods can communicate with other pods in cluster using the IP address without (NAT) Network Adress Translation. That is the IPs are preserved across the pod network.
4.  Network Isolation that restict each pod can communicate with defines using Network Policy.
5.  Referred as Flat Network.


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
