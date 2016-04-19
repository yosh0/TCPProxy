package main

import (
	"os"
	"fmt"
	"log"
	"net"
	"hash"
	"flag"
	"regexp"
	"strings"
	"syscall"
//	"io/ioutil"
	"os/signal"
	"crypto/md5"
	"crypto/rsa"
	"crypto/rand"
	"encoding/gob"
	"github.com/takama/daemon"
	"github.com/lumanetworks/go-tcp-proxy"
	"encoding/json"
)

const (
	_DN		= "goEPPd2"
	_DD		= "goEPPd2"
	_LT		= "\r\n"            	// packet line separator
	_LS		= "\x0D\x0A"	    	// Line serarators
	_KVT 		= ":"              	// header value separator
	_READ_BUF     	= 512              	// buffer size for socket reader
	_CMD_END      	= "--END COMMAND--"	// command data end

)

var (
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger
	localAddr   = flag.String("l", "127.0.0.1:7700", "local address")
	remoteAddr  = flag.String("r", "127.0.0.1:5038", "remote address")
	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles      = flag.Bool("n", false, "disable nagles algorithm")
	hex         = flag.Bool("h", false, "output hex")
	colors      = flag.Bool("c", true, "output ansi colors")
	unwrapTLS   = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match       = flag.String("match", "", "match regex (in the form 'regex')")
	replace     = flag.String("replace", "regex~replace", "replace regex (in the form 'regex~replacer')")
	stdlog, errlog *log.Logger
)

type Config struct {
	Conf Conf
}

type Conf struct {
	Port string
	Host string
	User string
	Pass string
}

type Service struct {
	daemon.Daemon
}


func (service *Service) Manage() (string, error) {
	usage := "Usage: myservice install | remove | start | stop | status"
	if len(os.Args) > 1 {
		command := os.Args[1]
		switch command {
		case "install":
			return service.Install()
		case "remove":
			return service.Remove()
		case "start":
			return service.Start()
		case "stop":
			return service.Stop()
		case "status":
			return service.Status()
		default:
			return usage, nil
		}
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, os.Kill, syscall.SIGTERM)
	flag.Parse()
	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
	}

	logger.Info("Proxying from %v to %v", *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		logger.Warn("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)

	if *veryverbose {
		*verbose = true
	}
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}
		connid++

		var p *proxy.Proxy
		if *unwrapTLS {
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Matcher = matcher
		p.Replacer = replacer

		p.Nagles = *nagles
		p.OutputHex = *hex
		p.Log = proxy.ColorLogger{
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
		}
		p.Start()

	}
	return usage, nil
}

func init() {
	private_key, err := os.Open("privategob.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	decoder := gob.NewDecoder(private_key)
	var privatekey *rsa.PrivateKey
	err = decoder.Decode(&privatekey)

	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	private_key.Close()

	file2, err := os.Open("config_cr.json")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	data2 := make([]byte, 1000)
	count2, err := file2.Read(data2)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	message2 := data2[:count2]
	file2.Close()

	decrypted := decrypt_oaep(privatekey, message2, []byte("123"))

//	var raw json.RawMessage
	conf := Config{}
	err = json.Unmarshal([]byte(decrypted), &conf)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("CONF")
	fmt.Println(conf)
	
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)
}

func main() {
	srv, err := daemon.New(_DN, _DD)
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(1)
	}
	service := &Service{srv}
	status, err := service.Manage()
	if err != nil {
		fmt.Println(status, "\nError: ", err)
		os.Exit(1)
	}
	fmt.Println(status)
}

func decrypt_oaep(private_key *rsa.PrivateKey, encrypted, label []byte) (decrypted []byte) {
	var err error
	var md5_hash hash.Hash

	md5_hash = md5.New()
	if decrypted, err = rsa.DecryptOAEP(md5_hash, rand.Reader, private_key, encrypted, label); err != nil {
		log.Fatal(err)
	}
	return
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
		if replace == "" {
			return nil
			fmt.Println(replace)
		}
		//split by / (TODO: allow slash escapes)
		parts := strings.Split(replace, "~")
		if len(parts) != 2 {
			logger.Warn("Invalid replace option")
			return nil
		}

		re, err := regexp.Compile(string(parts[0]))
		if err != nil {
			logger.Warn("Invalid replace regex: %s", err)
			return nil
		}

		repl := []byte(parts[1])

		logger.Info("Replacing %s with %s", re.String(), repl)
		return func(input []byte) []byte {
			return re.ReplaceAll(input, repl)
		}
}
