package webdav_ticket

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

func (d *WebDavTicket) isSharepoint() bool {
	return d.Vendor == "sharepoint"
}

func (d *WebDavTicket) setClient() error {
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
	controlAddress, err := d.authControlAddress()
	if err != nil {
		return err
	}
	d.authClient, err = d.newControlClient(controlAddress)
	if err != nil {
		return err
	}
	return nil
}

func (d *WebDavTicket) newControlClient(address string) (*gowebdav.Client, error) {
	client := gowebdav.NewClient(address, d.Username, d.Password)
	client.SetTransport(&http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: d.TlsInsecureSkipVerify},
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client.SetJar(jar)
	return client, nil
}

func (d *WebDavTicket) authControlAddress() (string, error) {
	return d.controlAddress(defaultWebDAVAuthControlPath)
}

func (d *WebDavTicket) authRevocationAddress() (string, error) {
	return d.controlAddress(defaultWebDAVAuthRevocationPath)
}

func (d *WebDavTicket) controlAddress(controlPath string) (string, error) {
	base, err := url.Parse(d.Address)
	if err != nil {
		return "", err
	}
	control, err := url.Parse(controlPath)
	if err != nil || control.IsAbs() || control.Host != "" || !strings.HasPrefix(control.Path, "/") {
		return "", fmt.Errorf("webdav auth control path is invalid: %q", controlPath)
	}
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
