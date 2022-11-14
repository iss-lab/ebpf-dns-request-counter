# dns-counter

### About 
This is a simple tool to count DNS request packets. The program uses the extended Berkeley Packet Filter (eBPF) to parse packet headers in the Linux express data path (XDP). When the packet is sent through the UDP protocol at port 53, the counter in the eBPF map is incremented by 1.

The Go program uses Dropbox's goebpf to interact with .elf files and manipulate eBPF programs and maps. The code is inspired by the examples provided by the goebpf repository. When running, it displays DNS packet counts in the terminal every second. In addition, count information is sent to InfluxDB simultaneously for further analysis.

### Requirements
Linux kernel version 4.15+

### Installation
#### Build Docker image
Before building the image, please update the InfluxDB URL in the .env file.
```
docker build -t ebpf-dns-request-counter .
```
#### Run metrics stack
```
docker-compose up -d
```
#### Configure metric stack
* Configure default datasource
```
curl -X POST --header "Content-Type: application/json" -d @./grafana_resources/datasources.json http://admin:admin@localhost:3000/api/datasources
```
Verify by logging into Grafana at `http://localhost:3000` with default username `admin` and password `admin`. From the left-hand side panel, select `Configuration` and then `Data sources`. You should have `InfluxDB` added as one of your data sources.

Click on the datasource and update the InfluxDB URL (with port 8086).
* Configure dashboard
```
curl -X POST --header "Content-Type: application/json" -d @./grafana_resources/dns-request-counter.json http://admin:admin@localhost:3000/api/dashboards/db
```
Revisit Grafana from the browser. From the same panel, select `Dashboards` and then `Manage`. You should see `DNS request counter` listed as one of your dashboards.

### Run eBPF
You can count either DNS requests made by your machine's network interface card (NIC), or by the container's NIC. Run `$ifconfig -a` to see a list of network interface names you can collect metrics on.
#### Run eBPF listening to machine's NIC
```
docker run --pid=host --cgroupns=host --network=host --privileged ebpf-dns-request-counter bash -c "./dns-request-counter --iface=<network interface name> --polling-interval=3 --send-to-db=on"
```
#### Run eBPF listening to container's NIC
```
docker run -it --pid=host --cgroupns=host --privileged --name=counter-container ebpf-dns-request-counter bash
```
Now you should have entered a shell, run the following to start the counter
```
./dns-request-counter --iface=<network interface name> --polling-interval=3 --send-to-db=on
```
In another terminal, enter the shell of the same docker container and generates some `dig`s and `ping`s!
```
docker exec -it counter-container bash
ping api.twitter.com
```

### Verify in dashboard
Access `http://localhost:3000/dashboards`, click on the `DNS request counter` dashboard and see the counts.
