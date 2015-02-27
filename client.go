package apns

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"time"
)

// You'll need to provide your own CertificateFile
// and KeyFile to send notifications. Ideally, you'll
// just set the CertificateFile and KeyFile fields to
// a location on drive where the certs can be loaded,
// but if you prefer you can use the CertificateBase64
// and KeyBase64 fields to store the actual contents.
type Client struct {
	Gateway           string
	CertificateFile   string
	CertificateBase64 string
	KeyFile           string
	KeyBase64         string
}

func ComboPEMClient(gateway, comboPEMFile string) (c *Client) {

	content, err := ioutil.ReadFile(comboPEMFile)

	if err != nil {
		fmt.Errorf("file read error", err)
		return
	}

	var certblock *pem.Block
	var keyblock *pem.Block

	certblock, content = pem.Decode(content)

	if certblock == nil {
		fmt.Errorf("no cert found")
		return
	}

	if len(content) == 0 {
		fmt.Errorf("no key")
		return
	}

	keyblock, content = pem.Decode(content)

	if err != nil {
		fmt.Errorf("no vaild key found")
		return
	}

	cert_pem := base64.StdEncoding.EncodeToString(certblock.Bytes)
	key_pem := base64.StdEncoding.EncodeToString(keyblock.Bytes)

	cert_pem = fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", cert_pem)
	key_pem = fmt.Sprintf("-----BEGIN RSA PRIVATE KEY-----\n%s\n-----END RSA PRIVATE KEY-----\n", key_pem)

	return BareClient(gateway, cert_pem, key_pem)
}

// Constructor. Use this if you want to set cert and key blocks manually.
func BareClient(gateway, certificateBase64, keyBase64 string) (c *Client) {
	c = new(Client)
	c.Gateway = gateway
	c.CertificateBase64 = certificateBase64
	c.KeyBase64 = keyBase64
	return
}

// Constructor. Use this if you want to load cert and key blocks from a file.
func NewClient(gateway, certificateFile, keyFile string) (c *Client) {
	c = new(Client)
	c.Gateway = gateway
	c.CertificateFile = certificateFile
	c.KeyFile = keyFile
	return
}

// Connects to the APN service and sends your push notification.
// Remember that if the submission is successful, Apple won't reply.
func (this *Client) Send(pn *PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)

	payload, err := pn.ToBytes()
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	err = this.ConnectAndWrite(resp, payload)
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	resp.Success = true
	resp.Error = nil

	return
}

// In lieu of a timeout (which would be available in Go 1.1)
// we use a timeout channel pattern instead. We start two goroutines,
// one of which just sleeps for TIMEOUT_SECONDS seconds, while the other
// waits for a response from the Apple servers.
//
// Whichever channel puts data on first is the "winner". As such, it's
// possible to get a false positive if Apple takes a long time to respond.
// It's probably not a deal-breaker, but something to be aware of.
func (this *Client) ConnectAndWrite(resp *PushNotificationResponse, payload []byte) (err error) {
	var cert tls.Certificate

	if len(this.CertificateBase64) == 0 && len(this.KeyBase64) == 0 {
		// The user did not specify raw block contents, so check the filesystem.
		cert, err = tls.LoadX509KeyPair(this.CertificateFile, this.KeyFile)

	} else {
		// The user provided the raw block contents, so use that.
		cert, err = tls.X509KeyPair([]byte(this.CertificateBase64), []byte(this.KeyBase64))
	}

	if err != nil {
		return err
	}

	conf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // add for error
	}

	conn, err := net.Dial("tcp", this.Gateway)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, conf)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	_, err = tlsConn.Write(payload)
	if err != nil {
		return err
	}

	// Create one channel that will serve to handle
	// timeouts when the notification succeeds.
	timeoutChannel := make(chan bool, 1)
	go func() {
		time.Sleep(time.Second * TIMEOUT_SECONDS)
		timeoutChannel <- true
	}()

	// This channel will contain the binary response
	// from Apple in the event of a failure.
	responseChannel := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 6, 6)
		conn.Read(buffer)
		responseChannel <- buffer
	}()

	// First one back wins!
	// The data structure for an APN response is as follows:
	//
	// command    -> 1 byte
	// status     -> 1 byte
	// identifier -> 4 bytes
	//
	// The first byte will always be set to 8.
	resp = NewPushNotificationResponse()
	select {
	case r := <-responseChannel:
		resp.Success = false
		resp.AppleResponse = APPLE_PUSH_RESPONSES[r[1]]
	case <-timeoutChannel:
		resp.Success = true
	}

	return nil
}
