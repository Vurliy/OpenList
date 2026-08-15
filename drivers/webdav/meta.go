package webdav

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

const defaultWebDAVAuthControlPath = "/webdav-auth/grants/"
const defaultWebDAVAuthRevocationPath = "/webdav-auth/revocations/"

type Addition struct {
	Vendor   string `json:"vendor" type:"select" options:"sharepoint,other" default:"other"`
	Address  string `json:"address" required:"true"`
	Username string `json:"username" required:"true"`
	Password string `json:"password" required:"true"`
	driver.RootPath
	TlsInsecureSkipVerify bool   `json:"tls_insecure_skip_verify" default:"false"`
	Thumbnail             bool   `json:"thumbnail" default:"false" help:"enable image and video thumbnails; requires HTTP Range support"`
	ThumbCacheFolder      string `json:"thumb_cache_folder" help:"optional local thumbnail cache folder"`
	VideoThumbPos         string `json:"video_thumb_pos" default:"20%" help:"video snapshot position in seconds or percentage"`
	WebDAVAuthEnabled     bool   `json:"webdav_auth_enabled" default:"false" help:"append signed tickets to direct WebDAV links"`
	WebDAVAuthSecret      string `json:"webdav_auth_secret" type:"text" help:"shared HMAC secret for the external WebDAV auth service"`
	WebDAVAuthAudience    string `json:"webdav_auth_audience" help:"ticket audience used to distinguish WebDAV services"`
	WebDAVAuthScope       string `json:"webdav_auth_scope" default:"/download" help:"public WebDAV path scope for browser links"`
	WebDAVAuthNonce       string `json:"webdav_auth_nonce" type:"text" help:"base64url nonce shared with the WebDAV ticket verifier"`
}

var config = driver.Config{
	Name:        "WebDav",
	LocalSort:   true,
	DefaultRoot: "/",
	PreferProxy: true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &WebDav{}
	})
}
