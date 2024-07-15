package grpc_server

import (
	context "context"
	g "github.com/gosnmp/gosnmp"
	pb "github.com/roxxxiey/proto/go"
	"google.golang.org/grpc"
	"log"
	"os"
	"time"
)

type serverAPI struct {
	pb.UnimplementedPollDriverServer
}

func Register(gRPC *grpc.Server) {
	pb.RegisterPollDriverServer(gRPC, &serverAPI{})
}

func (s *serverAPI) Poll(ctx context.Context, request *pb.PollRequest) (*pb.PollResponse, error) {
	log.Println("calling poll")

	// mode(v2c,v3),
	snmpSettings := request.GetSettings()

	switch snmpSettings[0].GetValue() {

	// v2c - ip, community
	case "v2c":
		log.Println("Get SNMPv2c version")
		ip := snmpSettings[1].GetValue()
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
			log.Fatalf("Connect() err: %v", err)
		}
		defer params.Conn.Close()

		response, err := s.oid(request, params)

		if err != nil {
			log.Fatalf("OID() err: %v", err)
		}
		return response, nil

	// v3 - ...
	case "v3":
		ip := snmpSettings[1].GetValue()
		log.Println("Get SNMPv3 version")
		params := &g.GoSNMP{
			Target:        ip,
			Port:          161,
			Version:       g.Version3,
			SecurityModel: g.UserSecurityModel,
			MsgFlags:      g.AuthPriv,
			Timeout:       time.Duration(30) * time.Second,
			SecurityParameters: &g.UsmSecurityParameters{UserName: "user",
				AuthenticationProtocol:   g.SHA,
				AuthenticationPassphrase: "password",
				PrivacyProtocol:          g.DES,
				PrivacyPassphrase:        "password",
			},
		}
		err := params.Connect()
		if err != nil {
			log.Fatalf("Connect() err: %v", err)
		}
		defer params.Conn.Close()

		response, err := s.oid(request, params)

		if err != nil {
			log.Fatalf("OID() err: %v", err)
		}
		return response, nil

	default:
		log.Println("This is not the SNMPv2c or SNMPv3")
	}

	return nil, nil
}

func (s *serverAPI) ChangeMetric(ctx context.Context, request *pb.ChangeMetricRequest) (*pb.ChangeMetricResponse, error) {
	log.Println("calling change")
	return nil, nil
}

func (s *serverAPI) Preset(ctx context.Context, request *pb.PresetRequest) (*pb.PresetResponse, error) {
	log.Println("calling preset")
	return nil, nil
}

// oid method for get OIDs
func (s *serverAPI) oid(request *pb.PollRequest, params *g.GoSNMP) (*pb.PollResponse, error) {
	log.Println("calling OID function")
	//Get OIDs
	var OIDs []string
	for _, item := range request.GetPollItem() {
		OIDs = append(OIDs, item.Addr)
	}

	log.Println("Was create OIDs massage:", OIDs)

	result, err := params.Get(OIDs) // Get() accepts up to g.MAX_OIDS

	if err != nil {
		log.Fatalf("Get() err: %v", err)
	}

	data := snmpParse(result)
	log.Println("Parsed SNMP data:", data)

	response := &pb.PollResponse{PollValue: make([]*pb.PollValue, len(OIDs))}

	for i, item := range request.GetPollItem() {
		response.PollValue[i] = &pb.PollValue{
			Addr:  item.Addr,
			Name:  item.Name,
			Value: data[i],
		}
	}

	return response, nil
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
