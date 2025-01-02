package main

import (
	"fmt"
	"flag"
	"net/smtp"
	"crypto"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"crypto/x509"
	"errors"
	"bytes"

	"gopkg.in/gomail.v2"
	"github.com/emersion/go-msgauth/dkim"
)

var (
	dkimSelect = flag.String("signselect", "default", "DKIM Selector")
	dkimDomain = flag.String("signdomain", "", "DKIM Domain")
	dkimPrivateKeyPath = flag.String("signkey", "", "Private key to use for DKIM signing")
	toAddr = flag.String("host", "", "SMTP domain and port to send email to")
	to = flag.String("to", "", "Receiver email address")
	from = flag.String("from", "", "Sender email address")
	subject = flag.String("subject", "Ping, now please pong", "Subject of the Message")
	message = flag.String("msg", "こんにちは、世界！", "Message to send")
)

func init() {
	flag.Parse()
}

func main() {
	if len(*dkimSelect) <= 0 {
		fmt.Println("-signselect not set")
		return
	}
	if len(*dkimDomain) <= 0 {
		fmt.Println("-signdomain not set")
		return
	}
	if len(*toAddr) <= 0 {
		fmt.Println("-host not set")
		return
	}
	if len(*to) <= 0 {
		fmt.Println("-to not set")
		return
	}
	if len(*from) <= 0 {
		fmt.Println("-from not set")
		return
	}
	fi, err := os.Stat(*dkimPrivateKeyPath)
	if err != nil {
		fmt.Printf("-signkey: %v", err)
		return
	}
	if fi.IsDir() {
		fmt.Println("-signkey: is a directory, expected a file")
		return
	}
	pk, err := parsePrivateKey(*dkimPrivateKeyPath)
	if err != nil {
		fmt.Println(err)
		return
	}
	m := Mailer{
		ToAddr: *toAddr,
		To: *to,
		From: *from,
		SignOpts: &dkim.SignOptions{
			Domain: *dkimDomain,
			Selector: *dkimSelect,
			Signer: pk,
		},
	}
	if err := m.SendMail(*subject, *message); err != nil {
		fmt.Printf("sending mail: %v", err)
	}
	fmt.Println("mail sent successfully")
}

func parsePrivateKey(file string) (crypto.Signer, error) {
	pkbs, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pkbs)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := key.(*rsa.PrivateKey); ok {
		return key, nil
	}
	return nil, errors.New("not an RSA private key")
}

type Mailer struct {
	ToAddr, From, To string
	SignOpts *dkim.SignOptions
}

func (m Mailer) SendMail(subject, message string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("From", m.From)
	msg.SetHeader("To", m.To)
	msg.SetHeader("Subject", subject)
	msg.SetBody("text/plain", message)
	var clearMessage, signedMessage bytes.Buffer
	if _, err := msg.WriteTo(&clearMessage); err != nil {
		return err
	}
	if err := dkim.Sign(&signedMessage, &clearMessage, m.SignOpts); err != nil {
		return err
	}
	if err := smtp.SendMail(m.ToAddr, nil, m.From, []string{m.To}, signedMessage.Bytes()); err != nil {
		return err
	}
	return nil
}
