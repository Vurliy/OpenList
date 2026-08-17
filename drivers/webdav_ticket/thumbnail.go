package webdav_ticket

import (
	"context"
	"errors"
	"net/url"
	"path"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/webdavauth"
)

const webDAVThumbExt = ".jpg"

func (d *WebDavTicket) thumbLink(_ context.Context, _ model.Obj) (*model.Link, error) {
	return nil, errors.New("webdav thumbnails are served by the remote thumbnail worker")
}

func (d *WebDavTicket) publicSourcePath(value string) string {
	root := path.Clean(d.GetRootPath())
	candidate := path.Clean(value)
	if root == "/" || candidate == root || strings.HasPrefix(candidate, root+"/") {
		return candidate
	}
	return path.Join(root, candidate)
}

func (d *WebDavTicket) thumbnailURL(ctx context.Context, sourcePath string) (string, error) {
	sourcePath = d.publicSourcePath(sourcePath)
	root := path.Clean(d.GetRootPath())
	relative := strings.TrimPrefix(sourcePath, root)
	relative = strings.TrimPrefix(relative, "/")
	if relative == "" || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return "", errors.New("invalid WebDAV thumbnail source path")
	}

	thumbnailPath := path.Join("/thumbnails", relative) + webDAVThumbExt
	scope := path.Join("/thumbnails", path.Dir(relative))
	if scope == "/thumbnails/." || scope == "/thumbnails/" {
		scope = "/thumbnails"
	}

	base, err := url.Parse(d.Address)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", errors.New("webdav address must include scheme and host")
	}
	base.Path = thumbnailPath
	base.RawPath = ""
	base.RawQuery = ""
	ticket, err := d.issueTicket(ctx, webdavauth.Ticket{
		Type:      webdavauth.TicketTypeDirectory,
		Scope:     scope,
		Recursive: true,
	})
	if err != nil {
		return "", err
	}
	query := base.Query()
	query.Set(webdavauth.QueryParameter, ticket)
	base.RawQuery = query.Encode()
	return base.String(), nil
}
