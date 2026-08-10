package webdav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/cron"
	"github.com/OpenListTeam/OpenList/v4/pkg/gowebdav"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/pkg/webdavauth"
)

type WebDav struct {
	model.Storage
	Addition
	client  *gowebdav.Client
	cron    *cron.Cron
	thumbMu sync.Mutex
}

func (d *WebDav) Config() driver.Config {
	return config
}

func (d *WebDav) GetAddition() driver.Additional {
	if d.WebDAVAuthTicketTTL <= 0 {
		d.WebDAVAuthTicketTTL = defaultWebDAVAuthTicketTTL
	}
	return &d.Addition
}

func (d *WebDav) Init(ctx context.Context) error {
	if d.WebDAVAuthEnabled {
		if d.WebDAVAuthSecret == "" {
			return errors.New("webdav auth is enabled but webdav_auth_secret is empty")
		}
		if d.WebDAVAuthTicketTTL <= 0 {
			d.WebDAVAuthTicketTTL = defaultWebDAVAuthTicketTTL
		}
	}
	err := d.setClient()
	if err == nil {
		d.cron = cron.NewCron(time.Hour * 12)
		d.cron.Do(func() {
			_ = d.setClient()
		})
	}
	return err
}

func (d *WebDav) Drop(ctx context.Context) error {
	if d.cron != nil {
		d.cron.Stop()
	}
	return nil
}

func (d *WebDav) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	files, err := d.client.ReadDir(dir.GetPath())
	if err != nil {
		return nil, err
	}
	return utils.SliceConvert(files, func(src os.FileInfo) (model.Obj, error) {
		obj := model.Obj(&model.Object{
			Path:     path.Join(dir.GetPath(), src.Name()),
			Name:     src.Name(),
			Size:     src.Size(),
			Modified: src.ModTime(),
			IsFolder: src.IsDir(),
		})
		if d.Thumbnail && !src.IsDir() && apiURL(ctx) != "" {
			fileType := utils.GetFileType(src.Name())
			if fileType == conf.IMAGE || fileType == conf.VIDEO {
				virtualPath := path.Join(args.ReqPath, src.Name())
				obj = &model.ObjThumb{
					Object:    *obj.(*model.Object),
					Thumbnail: model.Thumbnail{Thumbnail: thumbURL(ctx, virtualPath)},
				}
			}
		}
		return obj, nil
	})
}

func (d *WebDav) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if args.Type == "thumb" {
		return d.thumbLink(ctx, file)
	}
	url, header, err := d.client.Link(file.GetPath())
	if err != nil {
		return nil, err
	}
	if args.Redirect && d.WebDAVAuthEnabled {
		url, err = d.withWebDAVTicket(ctx, url)
		if err != nil {
			return nil, err
		}
	}
	if args.Redirect {
		// get the url after redirect
		req := base.NoRedirectClient.R()
		req.Header = header
		req.SetDoNotParseResponse(true)
		res, err := req.Get(url)
		if err != nil {
			return nil, err
		}
		_ = res.RawResponse.Body.Close()
		if (res.StatusCode() == 302 || res.StatusCode() == 307 || res.StatusCode() == 308) && res.Header().Get("location") != "" {
			url = res.Header().Get("location")
		} else if res.StatusCode() == http.StatusOK {
			// A normal WebDAV server returns the file itself with 200 rather
			// than redirecting. The URL is already a usable direct link, so do
			// not treat the successful response as a redirect failure.
		} else {
			return nil, fmt.Errorf("redirect failed, status: %d", res.StatusCode())
		}
	}
	return &model.Link{
		URL:    url,
		Header: header,
	}, nil
}

func (d *WebDav) withWebDAVTicket(ctx context.Context, rawURL string) (string, error) {
	user, ok := ctx.Value(conf.UserKey).(*model.User)
	if !ok || user == nil {
		return "", errors.New("cannot issue webdav ticket without an authenticated OpenList user")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	// The external WebDAV server authorizes its public URL path (for example
	// /download/movie.mp4), not the provider-internal path (/movie.mp4).
	// Signing file.GetPath() here would make a correctly signed ticket
	// unusable whenever Apache exposes the storage through an Alias.
	publicPath := u.Path
	if publicPath == "" || publicPath[0] != '/' {
		return "", errors.New("cannot issue webdav ticket without a public URL path")
	}
	now := time.Now()
	ticket, err := webdavauth.Issue(d.WebDAVAuthSecret, webdavauth.Ticket{
		Audience:  d.WebDAVAuthAudience,
		Path:      publicPath,
		UserID:    user.ID,
		Username:  user.Username,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Duration(d.WebDAVAuthTicketTTL) * time.Second).Unix(),
	})
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set(webdavauth.QueryParameter, ticket)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (d *WebDav) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	return d.client.MkdirAll(path.Join(parentDir.GetPath(), dirName), 0644)
}

func (d *WebDav) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	return d.client.Rename(getPath(srcObj), path.Join(dstDir.GetPath(), srcObj.GetName()), true)
}

func (d *WebDav) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	return d.client.Rename(getPath(srcObj), path.Join(path.Dir(srcObj.GetPath()), newName), true)
}

func (d *WebDav) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	return d.client.Copy(getPath(srcObj), path.Join(dstDir.GetPath(), srcObj.GetName()), true)
}

func (d *WebDav) Remove(ctx context.Context, obj model.Obj) error {
	return d.client.RemoveAll(getPath(obj))
}

func (d *WebDav) Put(ctx context.Context, dstDir model.Obj, s model.FileStreamer, up driver.UpdateProgress) error {
	callback := func(r *http.Request) {
		r.Header.Set("Content-Type", s.GetMimetype())
		r.ContentLength = s.GetSize()
	}
	reader := driver.NewLimitedUploadStream(ctx, &driver.ReaderUpdatingProgress{
		Reader:         s,
		UpdateProgress: up,
	})
	err := d.client.WriteStream(path.Join(dstDir.GetPath(), s.GetName()), reader, 0644, callback)
	return err
}

// implements driver.Getter interface
func (d *WebDav) Get(ctx context.Context, _path string) (model.Obj, error) {
	_path = path.Join(d.GetRootPath(), _path)
	info, err := d.client.Stat(_path)
	if err != nil {
		if gowebdav.IsErrNotFound(err) {
			return nil, errs.ObjectNotFound
		}
		return nil, err
	}

	return &model.Object{
		Name:     info.Name(),
		Size:     info.Size(),
		Modified: info.ModTime(),
		IsFolder: info.IsDir(),
		Path:     _path,
	}, nil
}

var _ driver.Driver = (*WebDav)(nil)
var _ driver.Getter = (*WebDav)(nil)
