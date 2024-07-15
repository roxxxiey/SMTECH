package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	g "github.com/gosnmp/gosnmp"
)

func main() {
	// Создание имитации SNMP-устройства
	params := &g.GoSNMP{
		Target:    "192.168.91.20",
		Port:      161,
		Community: "public",
		Version:   g.Version2c,
		Timeout:   time.Duration(2) * time.Second,
		Logger:    g.NewLogger(log.New(os.Stdout, "", 0)),
	}

	// Создание канала для прерывания работы по сигналу ОС
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Симуляция ответа на запросы
	for {
		listener, err := net.ListenUDP("udp", &net.UDPAddr{Port: 161})
		if err != nil {
			log.Printf("ListenUDP() err: %v", err)
			return
		}
		defer listener.Close()

		log.Println("SNMP simulator started")

		buffer := make([]byte, 1024)
		n, addr, err := listener.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("ReadFromUDP() err: %v", err)
			continue
		}

		fmt.Printf("Received request from %s: %s\n", addr, string(buffer[:n]))

		// Отправка реального SNMP ответа
		result, err := params.Get([]string{"1.3.6.1.2.1.1.1.0"}) // Пример OID для запроса
		if err != nil {
			log.Printf("Get() err: %v", err)
		} else {
			for _, variable := range result.Variables {
				fmt.Printf("OID: %s, Value: %s\n", variable.Name, variable.Value)
				// Здесь можно обработать значение и отправить его в ответ на запрос
			}
		}

		// Отправка имитированного ответа
		_, err = listener.WriteToUDP([]byte("Simulated response"), addr)
		if err != nil {
			log.Printf("WriteToUDP() err: %v", err)
		}

		// Ожидание сигнала для завершения работы
		select {
		case <-sig:
			log.Println("Received termination signal. Exiting...")
			return
		default:
		}
	}
}
