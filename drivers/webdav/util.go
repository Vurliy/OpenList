package webdav

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/drivers/webdav/odrvcookie"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/gowebdav"
)

// do others that not defined in Driver interface

func (d *WebDav) isSharepoint() bool {
	return d.Vendor == "sharepoint"
}

func (d *WebDav) setClient() error {
	c := gowebdav.NewClient(d.Address, d.Username, d.Password)
	c.SetTransport(&http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: d.TlsInsecureSkipVerify},
	})
	if d.isSharepoint() {
		cookie, err := odrvcookie.GetCookie(d.Username, d.Password, d.Address)
		if err == nil {
			c.SetInterceptor(func(method string, rq *http.Request) {
				rq.Header.Del("Authorization")
				rq.Header.Set("Cookie", cookie)
			})
		} else {
			return err
		}
	} else {
		cookieJar, err := cookiejar.New(nil)
		if err == nil {
			c.SetJar(cookieJar)
		} else {
			return err
		}
	}
	d.client = c
	if d.WebDAVAuthEnabled {
		controlAddress, err := d.authControlAddress()
		if err != nil {
			return err
		}
		authClient := gowebdav.NewClient(controlAddress, d.Username, d.Password)
		authClient.SetTransport(&http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: d.TlsInsecureSkipVerify},
		})
		controlJar, err := cookiejar.New(nil)
		if err != nil {
			return err
		}
		authClient.SetJar(controlJar)
		d.authClient = authClient
	} else {
		d.authClient = nil
	}
	return nil
}

func (d *WebDav) authControlAddress() (string, error) {
	base, err := url.Parse(d.Address)
	if err != nil {
		return "", err
	}
	control, err := url.Parse(defaultWebDAVAuthControlPath)
	if err != nil || control.IsAbs() || control.Host != "" || !strings.HasPrefix(control.Path, "/") {
		return "", fmt.Errorf("webdav auth control path is invalid: %q", defaultWebDAVAuthControlPath)
	}
	// The data client may still have a legacy /download/ suffix in Address.
	// The control client must always be rooted at the host, so deliberately
	// replace that data path with the fixed control path here.
	base.Path = path.Join("/", control.Path) + "/"
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return strings.TrimRight(base.String(), "/") + "/", nil
}

func getPath(obj model.Obj) string {
	if obj.IsDir() {
		return obj.GetPath() + "/"
	}
	return obj.GetPath()
}
