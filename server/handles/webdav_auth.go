package handles

import (
	"errors"

	webdavdriver "github.com/OpenListTeam/OpenList/v4/drivers/webdav"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
)

type webDAVAuthorizeReq struct {
	Ticket string `json:"ticket" binding:"required"`
	State  string `json:"state" binding:"required"`
}

// AuthorizeWebDAV completes the browser-side state binding. The browser
// authorization page calls this endpoint with the JWT already stored by the
// OpenList frontend. The endpoint never accepts a user identity from the
// client; it derives the identity from the authenticated request context.
func AuthorizeWebDAV(c *gin.Context) {
	var req webDAVAuthorizeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		common.ErrorResp(c, err, 400)
		return
	}
	user, ok := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !ok || user == nil || user.IsGuest() {
		common.ErrorStrResp(c, "OpenList login is required for WebDAV authorization", 401)
		return
	}
	rawToken, _ := c.Request.Context().Value(conf.TokenKey).(string)
	if rawToken == "" {
		common.ErrorStrResp(c, "OpenList authorization token is required", 401)
		return
	}

	var lastErr error
	for _, storage := range op.GetAllStorages() {
		driver, ok := storage.(*webdavdriver.WebDav)
		if !ok || !driver.WebDAVAuthEnabled {
			continue
		}
		redirectURL, err := driver.AuthorizeWebDAVState(req.Ticket, req.State, rawToken, user)
		if err == nil {
			common.SuccessResp(c, gin.H{"redirect_url": redirectURL})
			return
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no enabled WebDAV storage accepted this ticket")
	}
	common.ErrorResp(c, lastErr, 401)
}

// RevokeWebDAV invalidates every WebDAV browser session belonging to the
// current OpenList account. The revocation is published through each
// WebDAV storage's control credential; Apache remains the owner of its
// session files and applies the marker on the next request.
func RevokeWebDAV(c *gin.Context) {
	user, ok := c.Request.Context().Value(conf.UserKey).(*model.User)
	if !ok || user == nil || user.IsGuest() {
		common.ErrorStrResp(c, "OpenList login is required to revoke WebDAV sessions", 401)
		return
	}

	configured := false
	var lastErr error
	for _, storage := range op.GetAllStorages() {
		driver, ok := storage.(*webdavdriver.WebDav)
		if !ok || !driver.WebDAVAuthEnabled {
			continue
		}
		configured = true
		if err := driver.RevokeWebDAVUser(user); err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		common.ErrorResp(c, lastErr, 500)
		return
	}
	common.SuccessResp(c, gin.H{"configured": configured})
}
