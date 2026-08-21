package webdav_ticket

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
)

type Addition struct {
	Vendor   string `json:"vendor" type:"select" options:"other,sharepoint" default:"other"`
	Address  string `json:"address" required:"true" help:"WebDAV server public address, e.g. https://webdav-1.yourli.net"`
	Username string `json:"username" required:"true" help:"WebDAV admin username (credential A)"`
	Password string `json:"password" required:"true" help:"WebDAV admin password (credential A)"`
	driver.RootPath
	DirectMode              string `json:"direct_mode" type:"select" options:"cookie,direct" default:"cookie" help:"authorization mode: cookie session (secure) or pure stateless direct link"`
	WebDAVAuthSecret        string `json:"webdav_auth_secret" required:"true" type:"text" help:"shared HMAC secret with Apache mod_webdav_ticket"`
	WebDAVAuthAudience      string `json:"webdav_auth_audience" required:"true" help:"ticket audience used to distinguish WebDAV services (e.g. storage-1)"`
	WebDAVAuthNonce         string `json:"webdav_auth_nonce" type:"text" default:"fixed-v1" help:"base64url nonce shared with the WebDAV ticket verifier"`
	WebDAVAuthScope         string `json:"webdav_auth_scope" default:"/download" help:"public WebDAV path scope for browser links"`
	Thumbnail               bool   `json:"thumbnail" default:"true" help:"enable WebDAV thumbnails via worker"`
	ShowProxyPlayerButtons  bool   `json:"show_proxy_player_buttons" default:"true" help:"show OpenList backend proxy player buttons"`
	ShowDirectPlayerButtons bool   `json:"show_direct_player_buttons" default:"true" help:"show WebDAV direct player buttons with direct badge"`
	WebDAVDirectUsername    string `json:"webdav_direct_username" help:"WebDAV read-only credential B username for direct VLC/Infuse/nPlayer playback"`
	WebDAVDirectPassword    string `json:"webdav_direct_password" help:"WebDAV read-only credential B password for direct VLC/Infuse/nPlayer playback"`
	TlsInsecureSkipVerify   bool   `json:"tls_insecure_skip_verify" default:"false"`
}
