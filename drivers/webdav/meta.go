package webdav

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

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
