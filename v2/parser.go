package v2

type Parser interface {
	Parse(whoisText string) (WhoisInfo, error)
}

func NewParser(zone string) Parser {
	switch zone {
	case "md":
		return &MDParser{}
	case "ac":
		return &ACParser{}
	case "aero":
		return &AeroParser{}
	case "ai":
		return &AIParser{}
	default:
		return nil
	}
}
