package webdav_ticket

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

const defaultWebDAVAuthControlPath = "/webdav-auth/grants/"
const defaultWebDAVAuthRevocationPath = "/webdav-auth/revocations/"

var config = driver.Config{
	Name:        "WebDavTicket",
	LocalSort:   true,
	DefaultRoot: "/",
	PreferProxy: false,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &WebDavTicket{}
	})
}
