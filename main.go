package main

import (
	"fmt"
	"crypto/tls"
	"net"
	"encoding/binary"
	"io"
	"strings"
	"regexp"
	"io/ioutil"
	"time"
	"os/exec"
	"max-weller/vincy-server-go/vncauth"
)

var configDir string = "./config"

var onlineStatus map[string]string = make(map[string]string)

func main() {
	configDir = "/Users/mw/Projekte/node/vincy-server/config"
	
	go pingChecker()
	
	cert, _ := tls.LoadX509KeyPair(configDir + "/server-cert.pem", configDir + "/server-key.pem")
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	listener, err := tls.Listen("tcp", "127.0.0.1:8711", &config)
	if err != nil { fmt.Printf("listen error: %s\n", err); return }
	
	for {
		//var conn tls.Conn
	   	conn, err := listener.Accept()
		//conn = netconn
		if err != nil {
			fmt.Printf("server: accept: %s\n", err)
			break
		}
		fmt.Printf("--- server: accepted from %s\n", conn.RemoteAddr())
		go func() {
			defer conn.Close()
			defer func() {
				if r := recover(); r != nil {
					fmt.Println("[!!] Panic in handleConnection", r)
				}
			}()
			handleConnection(conn)
			fmt.Println("handleConnection done")
		}()
	}
	
}

func handleConnection(c net.Conn) {
	//fmt.Println("--- handleConnection -------------------------------")
	
	protocolGreet := readBytesBlock(c, 12)
	fmt.Printf("greet: %s\n", string(protocolGreet))

	ua := readVbStr(c)
	fmt.Printf("ua: %s\n", ua)
	
	c.Write([]byte("VINCY-SERVER"))
	
	// Flags
	flags := []byte{0x00, 0x00, 0x00, 0x04}
	c.Write(flags)
	
	client_key := readVbStr(c)
	fmt.Println("client_key",client_key)
	if !checkClientKey(client_key) {
		sendErrmes(c, "Unauthorized client")
		return
	}
	
	//reserved_flags
	_ = readUint16(c)
	
	auth_str := readVbStr(c)
	auth := strings.SplitN(auth_str, ":", 2)
	if len(auth) != 2 { sendErrmes(c, "Invalid auth"); return }
	
	username, password := auth[0], auth[1]
	
	fmt.Println("Auth:",username,password)
	
	hosts, err := readHostlist()
	if err != nil {
		sendErrmes(c, "Hostlist error: "+err.Error()); return
	}
	
	c.Write([]byte{0x00, 0x00}) // login ok
	
	command := readUint16(c)
	command_args := readVbStr(c)
	fmt.Println("Command:",command,command_args)
	
	switch command {
	case 0x01:
		c.Write([]byte{0x00, 0x00}) // command ok
		cmd_hostlist(hosts, c, command_args)
		break
	case 0x02:
		cmd_connectVnc(hosts, c, command_args)
		break
	default:
		sendErrmes(c, "Not implemented")
		break
	}
}


func cmd_hostlist(hosts HostList , c net.Conn, args string) {
	out := ""
	for _, host := range(hosts) {
		out += host.TabLine()+"\n"
	}
	sendVbStr(c, out)
}

func cmd_connectVnc(hosts HostList, c net.Conn, args string) {
	host := HostById(hosts, args)
	if host == nil {
		sendErrmes(c, "Host not found")
		return
	}
	target, err := net.DialTimeout("tcp", host.Hostname + ":" + host.VNCPort, 5*time.Second)
	fmt.Println("- CONNECTING TO VNC SERVER", host.Hostname, host.VNCPort)
	if (err != nil) {
		sendErrmes(c, "Connect failed: "+err.Error()); return;
	}
	
	target_prelude := readBytesBlock(target, 12)
	c.Write([]byte{0x00, 0x00}) // command ok
	c.Write(target_prelude)
	
	client_prelude := readBytesBlock(c, 12)
	target.Write(client_prelude)
	
	fmt.Println("- target:",string(target_prelude),"client:",string(client_prelude))
	
	assert(string(client_prelude) == "RFB 003.008\n", "wrong client version")
	assert(string(target_prelude) == "RFB 003.008\n", "wrong target version")
	
	// if version = 003.008
	c.Write([]byte{0x01, 0x01})
	sectype := readUint8(c)
	assert(sectype == 1, "wrong sectype")
	
	target_secTypeLen := readUint8(target)
	target_secTypes := readBytesBlock(target, int(target_secTypeLen))
	fmt.Println("- target secTypes:", target_secTypeLen, target_secTypes)
	target.Write([]byte{0x02})
	
	challenge := readBytesBlock(target, 16)
	target.Write(vncauth.VncAuthResponse(challenge, host.VNCPassword))
	
	target_secResult := readUint32(target)
	// received securityResponse 0x01 ? ...so there is an error
	if (target_secResult == 1) {
		errMes := readVbStrLong(target)
		c.Write([]byte{0x00,0x00,0x00,0x01})
		sendErrmes(c, fmt.Sprintln("Sec Error from target: ", errMes))
		panic (fmt.Sprintln("security fail from targetserver", errMes, errMes))
	}
	
	//send the securityResponse 0x00 - this means everything all right
	c.Write([]byte{0x00,0x00,0x00,0x00})
	fmt.Println("Success - going to connect pipes")
	
	go func(){
		_, _ = io.Copy(target, c)
		fmt.Println("Done from client")
		target.Close()
	}()
	_, _ = io.Copy(c, target)
	fmt.Println("Connection done from target")
	c.Close()
}

func HostById(hosts HostList, id string) *HostInfo {
	for _, host := range(hosts) {
		if host.ID == id {
			return &host
		}
	}
	return nil
}

func assert(cond bool, err string) {
	if !cond { panic(err) }
}

// File helper
var commentMatcher *regexp.Regexp
func init() {
	commentMatcher, _ = regexp.Compile("/^(#|\\/\\/)/")
}

type UserInfo struct {
	Username, Passwordhash string
	AllowedHosts []string
}
func readUsers() ([]UserInfo, error) {
	lines, err := readAllLines(configDir + "/vincypasswd")
	if err != nil { return nil, err }
	
	users := make([]UserInfo, 0, len(lines))
	for _, line := range(lines) {
		line = strings.TrimSpace(line)
		if line == "" || commentMatcher.MatchString(line) { continue }
		d := strings.Split(line, "\t")
		user := UserInfo{d[0], d[1], strings.Split(d[2], ",")}
		users = append(users, user)
	}
	
	return users, nil
}


type HostList []HostInfo;
type HostInfo struct {
	ID, Hostname, Group, VNCPort, VNCPassword, MacAddress, Comment string
}
func (h *HostInfo) TabLine() string {
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s", 
			h.ID, h.Hostname, h.Group, onlineStatus[h.ID], h.MacAddress, h.Comment)
}
func readHostlist() (HostList, error) {
	lines, err := readAllLines(configDir + "/hostlist.txt")
	if err != nil { return nil, err }
	
	hosts := make(HostList, 0, len(lines))
	for _, line := range(lines) {
		line = strings.TrimSpace(line)
		if line == "" || commentMatcher.MatchString(line) { continue }
		d := append(strings.Split(line, "\t"), "", "", "", "", "", "", "", "", "")
		host := HostInfo{d[0], d[1], d[2], d[3], d[4], d[5], d[8]}
		hosts = append(hosts, host)
	}
	
	return hosts, nil
}


func checkClientKey(key string) bool {
	lines, err := readAllLines(configDir + "/authorized_clients")
	if err != nil {
		fmt.Println("Error checking client key", key, err);
		return false
	}
	if len(key) != 64 { return false }
	for _, line := range(lines) {
		line = strings.TrimSpace(line)
		if line == "" || commentMatcher.MatchString(line) { continue }
		if strings.TrimSpace(line) == key {
			return true
		}
	}
	return false
}

func readAllLines(filename string) ([]string, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil { return nil, err }
	lines := strings.Split(string(content), "\n")
	return lines, nil
}

// Protocol helper
func sendErrmes(c net.Conn, message string) {
	fmt.Println("ERR MES: ", message)
	sendVbStr(c, message)
}
func sendVbStr(c net.Conn, str string) {
	binary.Write(c, binary.BigEndian, uint16(len(str)))
	c.Write([]byte(str))
}



// Protocol parsing

func readUint8(c net.Conn) uint8 {
	buf := readBytesBlock(c, 1)
	return buf[0]
}
func readUint16(c net.Conn) uint16 {
	buf := readBytesBlock(c, 2)
	return binary.BigEndian.Uint16(buf)
}
func readUint32(c net.Conn) uint32 {
	buf := readBytesBlock(c, 4)
	return binary.BigEndian.Uint32(buf)
}
func readVbStr(c net.Conn) string {
	buf := readBytesBlock(c, 2)
	strlen := int(binary.BigEndian.Uint16(buf))
	buf = readBytesBlock(c, strlen)
	return string(buf)
}

func readVbStrLong(c net.Conn) string {
	buf := readBytesBlock(c, 4)
	strlen := int(binary.BigEndian.Uint32(buf))
	buf = readBytesBlock(c, strlen)
	return string(buf)
}

func readBytesBlock(conn net.Conn, requestedBytes int) ([]byte) {
	buf := make([]byte, 0, requestedBytes)
	readBytes := 0
	for requestedBytes > readBytes {
		//fmt.Print("\treadBytesBlock ", requestedBytes, readBytes)
		tmp := make([]byte, requestedBytes - readBytes)
		len, err := conn.Read(tmp)
		//fmt.Println("in: ", len, tmp)

		if err != nil {
			if err != io.EOF {
			  fmt.Println("read error:", err)
			}
			panic(fmt.Sprintf("%s", err.Error()))
			break
		}
		readBytes += len
		buf = append(buf, tmp[:len]...)
	}
	//fmt.Println("  Result: ", buf)
	return buf
}


// Background task
func pingChecker() {
	for {
		hosts, err := readHostlist()
		if err != nil {
			fmt.Println("Unable to read hostlist", err)
			continue
		}
		
		for _, host := range(hosts) {
			pinger := exec.Command("ping", "-c", "1", "-t", "2", host.Hostname)
			err := pinger.Run()
			if err == nil {
				onlineStatus[host.ID] = "true"
				//fmt.Println("host online", host.ID)
			} else {
				switch t := err.(type) {
				default: fmt.Printf("Unexpected error: %s", err)
				case *exec.ExitError:
					onlineStatus[host.ID] = "false"
					_ = t
					//fmt.Println("host offline", host.ID, t)
				}
			}
		}

		time.Sleep(time.Minute)
	}
}







