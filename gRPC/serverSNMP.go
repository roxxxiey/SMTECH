package grpc_server

import (
	context "context"
	"fmt"
	g "github.com/gosnmp/gosnmp"
	pb "github.com/roxxxiey/proto/go"
	"google.golang.org/grpc"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type serverAPISNMP struct {
	pb.UnimplementedPollDriverServiceServer
}

func Register(gRPC *grpc.Server) {
	pb.RegisterPollDriverServiceServer(gRPC, &serverAPISNMP{})
}

func (s *serverAPISNMP) PollType(ctx context.Context, request *pb.PollTypeRequest) (*pb.PollTypeResponse, error) {
	log.Println("calling pollType")
	return nil, nil
}

func (s *serverAPISNMP) Poll(ctx context.Context, request *pb.PollRequest) (*pb.PollResponse, error) {
	log.Println("calling poll")

	// mode(v2c,v3),
	snmpSettings := request.GetSettings()
	if len(snmpSettings) < 3 || len(snmpSettings) > 7 {
		return nil, fmt.Errorf("invalid settings")
	}

	switch snmpSettings[0].GetValue() {

	// v2c - ip, community
	case "v2c":

		log.Println("Get SNMPv2c version")
		ip := snmpSettings[1].GetValue()
		if isValidIPv4(ip) != true {
			return nil, fmt.Errorf("invalid IP")
		}
		community := snmpSettings[2].GetValue()
		params := &g.GoSNMP{
			Target:    ip,
			Port:      161,
			Community: community,
			Version:   g.Version2c,
			Timeout:   time.Duration(2) * time.Second,
			Logger:    g.NewLogger(log.New(os.Stdout, "", 0)),
		}
		err := params.Connect()
		if err != nil {
			return nil, fmt.Errorf("SNMP connect err: %v", err)
		}
		defer params.Conn.Close()

		response, err := s.oid(request, params)

		if err != nil {
			return nil, fmt.Errorf("problem with getOIDs v2c: %v", err)
		}
		return response, nil

	// v3 - ...
	case "v3":

		ip := snmpSettings[1].GetValue()
		if isValidIPv4(ip) != true {
			return nil, fmt.Errorf("invalid IP")
		}
		userName := snmpSettings[2].GetValue()
		authentication := map[string]int{
			"NoAuth": 1,
			"MD5":    2,
			"SHA":    3,
			"SHA224": 4,
			"SHA256": 5,
			"SHA384": 6,
			"SHA512": 7,
		}
		authPassword := snmpSettings[4].GetValue()
		encryption := map[string]int{
			"NoPriv":  1,
			"DES":     2,
			"AES":     3,
			"AES192":  4,
			"AES256":  5,
			"AES192C": 6,
			"AES256C": 7,
		}
		privatePassword := snmpSettings[6].GetValue()

		log.Println("Get SNMPv3 version")
		params := &g.GoSNMP{
			Target:        ip,
			Port:          161,
			Version:       g.Version3,
			SecurityModel: g.UserSecurityModel,
			MsgFlags:      g.AuthPriv,
			Timeout:       time.Duration(30) * time.Second,
			SecurityParameters: &g.UsmSecurityParameters{
				UserName:                 userName,
				AuthenticationProtocol:   g.SnmpV3AuthProtocol(authentication[snmpSettings[3].GetValue()]),
				AuthenticationPassphrase: authPassword,
				PrivacyProtocol:          g.SnmpV3PrivProtocol(encryption[snmpSettings[5].GetValue()]),
				PrivacyPassphrase:        privatePassword,
			},
		}
		err := params.Connect()
		if err != nil {
			return nil, fmt.Errorf("SNMP connect err: %v", err)
		}
		defer params.Conn.Close()

		response, err := s.oid(request, params)

		if err != nil {
			return nil, fmt.Errorf("problem with getOIDs v3: %v", err)
		}
		return response, nil

	default:
		log.Println("This is not the SNMPv2c or SNMPv3")
	}

	return nil, nil
}

func (s *serverAPISNMP) ChangeMetric(ctx context.Context, request *pb.ChangeMetricRequest) (*pb.ChangeMetricResponse, error) {
	log.Println("calling change")
	return nil, nil
}

func (s *serverAPISNMP) Preset(ctx context.Context, request *pb.PresetRequest) (*pb.PresetResponse, error) {
	log.Println("calling preset")
	return nil, nil
}

// oid method for get OIDs
func (s *serverAPISNMP) oid(request *pb.PollRequest, params *g.GoSNMP) (*pb.PollResponse, error) {
	log.Println("calling OID function")
	//Get OIDs
	pollItems := request.GetPollItems()
	var OIDs []string
	for _, item := range pollItems {
		OIDs = append(OIDs, item.Addr)
	}

	result, err := params.Get(OIDs) // Get() accepts up to g.MAX_OIDS

	if err != nil {
		return nil, fmt.Errorf("get OIDs err --159 string--: %v", err)
	}

	data := snmpParse(result)

	for i, item := range pollItems {
		item.Value = &data[i]
	}

	return &pb.PollResponse{
		PollItem: pollItems,
	}, nil
}

func snmpParse(packet *g.SnmpPacket) []string {
	data := []string{}
	for _, variable := range packet.Variables {
		switch variable.Type {
		case g.OctetString:
			data = append(data, string(variable.Value.([]byte)))
		case g.ObjectIdentifier:
			data = append(data, variable.Value.(string))
		case g.TimeTicks:
			data = append(data, g.ToBigInt(variable.Value).String())
		case g.Integer:
			data = append(data, g.ToBigInt(variable.Value).String())
		case g.Counter32:
			data = append(data, g.ToBigInt(variable.Value).String())
		case g.Counter64:
			value := g.ToBigInt(variable.Value)
			value.Div(value, g.ToBigInt(1024))
			data = append(data, value.String())
		default:
			data = append(data, g.ToBigInt(variable.Value).String())
		}
	}
	return data
}

func isValidIPv4(ip string) bool {
	// Проверяем, является ли IP действительным и не является ли он nil
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Проверяем, что это IPv4, а не IPv6
	if strings.Contains(ip, ":") {
		return false
	}

	// Проверяем, что IP в формате x.x.x.x и каждая часть от 0 до 255
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
	}

	return true
}
