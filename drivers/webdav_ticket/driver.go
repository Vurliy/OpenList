package webdav_ticket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/cron"
	"github.com/OpenListTeam/OpenList/v4/pkg/gowebdav"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/pkg/webdavauth"
)

type WebDavTicket struct {
	model.Storage
	Addition
	client           *gowebdav.Client
	authClient       *gowebdav.Client
	cron             *cron.Cron
	ticketMu         sync.RWMutex
	directoryTickets map[string]string
}

func (d *WebDavTicket) Config() driver.Config {
	return config
}

func (d *WebDavTicket) GetAddition() driver.Additional {
	if d.WebDAVAuthScope == "" {
		d.WebDAVAuthScope = "/download"
	}
	if d.WebDAVAuthNonce == "" {
		d.WebDAVAuthNonce = webdavauth.DefaultAuthNonce
	}
	return &d.Addition
}

func (d *WebDavTicket) Init(ctx context.Context) error {
	if d.WebDAVAuthSecret == "" {
		return errors.New("webdav_auth_secret is required for WebDavTicket storage")
	}
	if d.WebDAVAuthAudience == "" {
		return errors.New("webdav_auth_audience is required for WebDavTicket storage")
	}
	if d.WebDAVAuthScope == "" {
		d.WebDAVAuthScope = "/download"
	}
	if _, err := webdavauth.CanonicalPath(d.WebDAVAuthScope); err != nil {
		return fmt.Errorf("invalid webdav_auth_scope: %w", err)
	}
	var err error
	d.WebDAVAuthNonce, err = webdavauth.NormalizeNonce(d.WebDAVAuthNonce)
	if err != nil {
		return fmt.Errorf("invalid webdav_auth_nonce: %w", err)
	}
	err = d.setClient()
	if err == nil {
		d.cron = cron.NewCron(time.Hour * 12)
		d.cron.Do(func() {
			_ = d.setClient()
		})
	}
	return err
}

func (d *WebDavTicket) Drop(ctx context.Context) error {
	if d.cron != nil {
		d.cron.Stop()
	}
	return nil
}

func (d *WebDavTicket) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
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
		if !src.IsDir() {
			fileType := utils.GetFileType(src.Name())
			var thumbnailURL string
			if d.Thumbnail && (fileType == conf.IMAGE || fileType == conf.VIDEO) {
				thumbnailURL, _ = d.thumbnailURL(ctx, obj.GetPath())
			}
			rawFileURL, _, _ := d.client.Link(obj.GetPath())
			var fileDirectURL string
			if rawFileURL != "" {
				fileDirectURL, _ = d.withWebDAVTicket(ctx, rawFileURL)
			}
			if thumbnailURL != "" && fileDirectURL != "" {
				obj = &model.ObjThumbURL{
					Object:    *obj.(*model.Object),
					Thumbnail: model.Thumbnail{Thumbnail: thumbnailURL},
					Url:       model.Url{Url: fileDirectURL},
				}
			} else if thumbnailURL != "" {
				obj = &model.ObjThumb{
					Object:    *obj.(*model.Object),
					Thumbnail: model.Thumbnail{Thumbnail: thumbnailURL},
				}
			} else if fileDirectURL != "" {
				obj = &model.ObjectURL{
					Object: *obj.(*model.Object),
					Url:    model.Url{Url: fileDirectURL},
				}
			}
		}
		return obj, nil
	})
}

func (d *WebDavTicket) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if args.Type == "thumb" {
		return d.thumbLink(ctx, file)
	}
	url, header, err := d.client.Link(file.GetPath())
	if err != nil {
		return nil, err
	}
	if args.Redirect {
		url, err = d.withWebDAVTicket(ctx, url)
		if err != nil {
			if ctx.Value(conf.TokenKey) == nil {
				return &model.Link{
					URL:    url,
					Header: header,
				}, nil
			}
			return nil, err
		}
	}
	return &model.Link{
		URL:    url,
		Header: header,
	}, nil
}

func (d *WebDavTicket) issueTicket(ctx context.Context, ticket webdavauth.Ticket) (string, error) {
	user, ok := ctx.Value(conf.UserKey).(*model.User)
	if !ok || user == nil || user.IsGuest() {
		return "", errors.New("cannot issue webdav ticket without an authenticated OpenList user")
	}
	rawToken, _ := ctx.Value(conf.TokenKey).(string)
	if rawToken == "" {
		return "", errors.New("cannot issue webdav ticket without the OpenList authorization token")
	}
	if ticket.Scope == "" {
		ticket.Scope = d.WebDAVAuthScope
	}
	if ticket.Scope == "" {
		ticket.Scope = "/download"
	}
	ticket.Audience = d.WebDAVAuthAudience
	ticket.UserID = user.ID
	ticket.TokenDigest = webdavauth.TokenDigest(rawToken)
	ticket.Generation = webdavauth.AuthGeneration
	if ticket.Type == webdavauth.TicketTypeDirectory {
		key := fmt.Sprintf("%s|%s|%d|%s|%s|%t|%s", ticket.Type, ticket.Audience,
			ticket.UserID, ticket.TokenDigest, ticket.Scope, ticket.Recursive, ticket.Generation)
		d.ticketMu.RLock()
		cached := d.directoryTickets[key]
		d.ticketMu.RUnlock()
		if cached != "" {
			return cached, nil
		}
		issued, err := webdavauth.IssuePathBound(d.WebDAVAuthSecret, d.WebDAVAuthNonce, ticket)
		if err != nil {
			return "", err
		}
		d.ticketMu.Lock()
		if d.directoryTickets == nil {
			d.directoryTickets = make(map[string]string)
		}
		if len(d.directoryTickets) >= 1024 {
			for oldKey := range d.directoryTickets {
				delete(d.directoryTickets, oldKey)
				break
			}
		}
		d.directoryTickets[key] = issued
		d.ticketMu.Unlock()
		return issued, nil
	}
	return webdavauth.IssuePathBound(d.WebDAVAuthSecret, d.WebDAVAuthNonce, ticket)
}

func (d *WebDavTicket) withWebDAVTicket(ctx context.Context, rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	publicPath, err := webdavauth.CanonicalPath(u.Path)
	if err != nil {
		return "", fmt.Errorf("cannot issue webdav ticket without a public URL path: %w", err)
	}
	ticket, err := d.issueTicket(ctx, webdavauth.Ticket{
		Type:  webdavauth.TicketTypeFile,
		Path:  publicPath,
		Scope: d.WebDAVAuthScope,
	})
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set(webdavauth.QueryParameter, ticket)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func (d *WebDavTicket) writeWebDAVGrant(ticket string, user *model.User, tokenDigest, state string) (string, error) {
	if d.authClient == nil {
		return "", errors.New("webdav auth control client is not initialized")
	}
	claims, err := webdavauth.VerifyPathBound(d.WebDAVAuthSecret, d.WebDAVAuthNonce, ticket, "")
	if err != nil {
		return "", fmt.Errorf("verify webdav grant before upload: %w", err)
	}
	if claims.Audience != d.WebDAVAuthAudience || claims.TokenDigest != tokenDigest {
		return "", errors.New("webdav grant identity does not match the current OpenList token")
	}
	grantID, err := webdavauth.NewGrantID()
	if err != nil {
		return "", fmt.Errorf("generate webdav grant id: %w", err)
	}
	now := time.Now().Unix()
	claims.TokenDigest = tokenDigest
	grant, err := webdavauth.NewGrant(grantID, ticket, d.WebDAVAuthNonce, state, claims, now, now+300)
	if err != nil {
		return "", err
	}
	grant.UserID = user.ID
	grant.Signature = webdavauth.SignGrant(d.WebDAVAuthSecret, grant)
	data, err := json.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("marshal webdav grant: %w", err)
	}
	name := fmt.Sprintf("%s.json", grantID)
	tmp := "tmp-" + name
	if err := d.authClient.Write(tmp, data, 0600); err != nil {
		return "", fmt.Errorf("write webdav grant: %w", err)
	}
	if err := d.authClient.Rename(tmp, name, true); err != nil {
		return "", fmt.Errorf("publish webdav grant: %w", err)
	}
	return grantID, nil
}

func (d *WebDavTicket) AuthorizeWebDAVState(ticket, state string, args ...any) (string, error) {
	if state == "" {
		return "", errors.New("webdav authorization state is empty")
	}
	var rawToken string
	var user *model.User
	if len(args) == 2 {
		rawToken, _ = args[0].(string)
		user, _ = args[1].(*model.User)
	} else if len(args) == 1 {
		user, _ = args[0].(*model.User)
		if user != nil {
			rawToken = user.Username
		}
	}
	if rawToken == "" {
		return "", errors.New("OpenList authorization token is empty")
	}
	claims, err := webdavauth.VerifyPathBound(d.WebDAVAuthSecret, d.WebDAVAuthNonce, ticket, "")
	if err != nil {
		return "", fmt.Errorf("verify webdav authorization ticket: %w", err)
	}
	if user == nil || user.IsGuest() || claims.UserID != user.ID {
		return "", errors.New("webdav authorization user mismatch")
	}
	grantID, err := d.writeWebDAVGrant(ticket, user, claims.TokenDigest, state)
	if err != nil {
		return "", err
	}
	return d.webDAVExchangeURL(ticket, state, grantID)
}

func (d *WebDavTicket) RevokeWebDAVUser(user *model.User) error {
	if user == nil || user.IsGuest() {
		return nil
	}
	address, err := d.authRevocationAddress()
	if err != nil {
		return err
	}
	client, err := d.newControlClient(address)
	if err != nil {
		return err
	}
	data, err := json.Marshal(map[string]any{
		"v":          1,
		"uid":        user.ID,
		"revoked_at": time.Now().Unix(),
	})
	if err != nil {
		return err
	}
	name := fmt.Sprintf("user-%d.json", user.ID)
	tmp := "tmp-" + name
	if err := client.Write(tmp, data, 0600); err != nil {
		return fmt.Errorf("write WebDAV revocation marker: %w", err)
	}
	if err := client.Rename(tmp, name, true); err != nil {
		return fmt.Errorf("publish WebDAV revocation marker: %w", err)
	}
	return nil
}

func (d *WebDavTicket) webDAVExchangeURL(ticket, state, grantID string) (string, error) {
	base, err := url.Parse(d.Address)
	if err != nil {
		return "", err
	}
	if base.Scheme == "" || base.Host == "" {
		return "", errors.New("webdav address must include scheme and host")
	}
	base.Path = "/webdav-auth/exchange"
	query := base.Query()
	query.Set(webdavauth.QueryParameter, ticket)
	query.Set("state", state)
	query.Set("grant_id", grantID)
	base.RawQuery = query.Encode()
	base.Fragment = ""
	return base.String(), nil
}

func (d *WebDavTicket) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	return d.client.MkdirAll(path.Join(parentDir.GetPath(), dirName), 0644)
}

func (d *WebDavTicket) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	return d.client.Rename(getPath(srcObj), path.Join(dstDir.GetPath(), srcObj.GetName()), true)
}

func (d *WebDavTicket) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	return d.client.Rename(getPath(srcObj), path.Join(path.Dir(srcObj.GetPath()), newName), true)
}

func (d *WebDavTicket) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	return d.client.Copy(getPath(srcObj), path.Join(dstDir.GetPath(), srcObj.GetName()), true)
}

func (d *WebDavTicket) Remove(ctx context.Context, obj model.Obj) error {
	return d.client.RemoveAll(getPath(obj))
}

func (d *WebDavTicket) Put(ctx context.Context, dstDir model.Obj, s model.FileStreamer, up driver.UpdateProgress) error {
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

func (d *WebDavTicket) Get(ctx context.Context, _path string) (model.Obj, error) {
	_path = path.Join(d.GetRootPath(), _path)
	info, err := d.client.Stat(_path)
	if err != nil && _path != "/" && _path[len(_path)-1] != '/' && isDirectoryStatRedirect(err) {
		info, err = d.client.Stat(_path + "/")
	}
	if err != nil {
		if gowebdav.IsErrNotFound(err) {
			return nil, errs.ObjectNotFound
		}
		return nil, err
	}

	name := info.Name()
	if name == "" && _path != "/" {
		name = path.Base(_path)
	}

	obj := &model.Object{
		Name:     name,
		Size:     info.Size(),
		Modified: info.ModTime(),
		IsFolder: info.IsDir(),
		Path:     _path,
	}
	url, _, err := d.client.Link(obj.GetPath())
	if err == nil {
		rawURL, err := d.withWebDAVTicket(ctx, url)
		if err == nil {
			return &model.ObjectURL{
				Object: *obj,
				Url:    model.Url{Url: rawURL},
			}, nil
		}
	}
	return obj, nil
}

func isDirectoryStatRedirect(err error) bool {
	for _, status := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
		http.StatusNotFound,
	} {
		if gowebdav.IsErrCode(err, status) {
			return true
		}
	}
	return false
}

var _ driver.Driver = (*WebDavTicket)(nil)
var _ driver.Getter = (*WebDavTicket)(nil)
var _ driver.WebDAVTicketAuthorizer = (*WebDavTicket)(nil)
