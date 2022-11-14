package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/dropbox/goebpf"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
	"github.com/spf13/viper"
)

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var pollingInterval = flag.Int("polling-interval", 1, "Interval (unit: second(s)) to count the number of DNS requests")
var elf = flag.String("elf", "ebpf_prog/xdp.elf", "clang/llvm compiled binary file")
var programName = flag.String("program", "packet_count", "Name of XDP program (function name)")
var influxDB = flag.String("send-to-db", "off", "enable data to be sent to InfluxDB")

type database struct {
	client   influxdb2.Client
	p        *write.Point
	writeAPI api.WriteAPI
}

type envVariables struct {
	myToken  string
	myBucket string
	myOrg    string
	myAddr   string
}

func getEnvVariables(key string) string {
	viper.SetConfigFile(".env")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error while reading config file %s", err)
	}
	value, ok := viper.Get(key).(string)
	if !ok {
		log.Fatalf("Invalid type assertion")
	}
	return value
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

func writeToInflux(db *database, val int, delta int, intvl int) {
	db.p = influxdb2.NewPointWithMeasurement("dns request").
		AddTag("unit", "count").
		AddField("cumulated count", val).
		AddField("requests during the last interval", delta).
		AddField("interval", intvl).
		SetTime(time.Now())
	db.writeAPI.WritePoint(db.p)
	db.writeAPI.Flush()
	fmt.Println("data saved to influxDB\n")
}

func main() {

	flag.Parse()
	if *iface == "" {
		fatalError("-iface is required.")
	}

	// update polling interval
	var interval = 1 * time.Second
	if *pollingInterval != 1 {
		interval *= time.Duration(*pollingInterval)
	}

	// enable/disable InfluxDB feature
	envVar := &envVariables{myToken: getEnvVariables("DOCKER_INFLUXDB_INIT_ADMIN_TOKEN"),
		myBucket: getEnvVariables("DOCKER_INFLUXDB_INIT_BUCKET"),
		myOrg:    getEnvVariables("DOCKER_INFLUXDB_INIT_ORG"),
		myAddr:   getEnvVariables("MY_ADDR")}
	db := &database{}
	switch toDB := *influxDB; toDB {
	case "on":
		db.client = influxdb2.NewClient(envVar.myAddr+":8086", envVar.myToken)
		db.p = &write.Point{}
		fmt.Println("\n\t**InfluxDB feature enabled**\n")
		break
	case "off":
		envVar = nil
		db = nil
		fmt.Println("\n\t**InfluxDB feature disabled**\n")
		break
	default:
		fatalError("only specify on or off for InfluxDB feature")
	}

	// Create eBPF system / load .ELF files compiled by clang/llvm
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	// Find rqCounter eBPF map
	dnsRq := bpf.GetMapByName("rqCounter")
	if dnsRq == nil {
		fatalError("eBPF map 'rqCounter' not found")
	}

	// Program name matches function name in xdp.c:
	//      int packet_count(struct xdp_md *ctx)
	xdp := bpf.GetProgramByName(*programName)
	if xdp == nil {
		fatalError("Program '%s' not found.", *programName)
	}

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	// Print stat every second / exit on CTRL+C
	fmt.Printf("XDP program successfully loaded and attached. Counter refreshes every %d second(s)\n", *pollingInterval)
	fmt.Println()
	ticker := time.NewTicker(interval)

	var diff int = 0

	for {
		if db != nil {
			db.writeAPI = db.client.WriteAPI(envVar.myOrg, envVar.myBucket)
		}

		select {
		case <-ticker.C:

			i := 0
			value, err := dnsRq.LookupInt(i)
			if err != nil {
				fatalError("LookupInt failed: %v", err)
			}
			if value > 0 {
				fmt.Printf("%s: %d\n", "Number of total DNS requests", value)
				fmt.Printf("Number of DNS requests in the past %d second(s): %d\n", *pollingInterval, value-diff)
				fmt.Println()

				if db != nil {
					writeToInflux(db, value, value-diff, *pollingInterval)
				}

				diff = value

			}
			fmt.Printf("\r")
		case <-ctrlC:
			return
		}

		if db != nil {
			db.client.Close()
		}
	}
}
