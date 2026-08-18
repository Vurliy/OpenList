package webdav_ticket

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/model"
	log "github.com/sirupsen/logrus"
)

type dirSizeQueryReq struct {
	DirPath string `json:"dir_path"`
	Force   bool   `json:"force"`
}

type dirSizeQueryResp struct {
	Status              string           `json:"status"`
	TotalSize           int64            `json:"total_size"`
	DirectChildrenSizes map[string]int64 `json:"direct_children_sizes"`
	CalculatedAt        int64            `json:"calculated_at"`
	ExpiresAt           int64            `json:"expires_at"`
	RetryAfterSeconds   int              `json:"retry_after_seconds,omitempty"`
}

type diskUsageResp struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
	Free  int64 `json:"free"`
}

func (d *WebDavTicket) httpClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: d.TlsInsecureSkipVerify,
			},
		},
	}
}

func (d *WebDavTicket) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	if d.Address == "" {
		return nil, fmt.Errorf("webdav address is empty")
	}
	apiURL := strings.TrimRight(d.Address, "/") + "/dirsize-api/v1/disk_usage"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(d.Username, d.Password)

	client := d.httpClient(3 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		log.Warnf("[WebDavTicket] GetDetails error: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warnf("[WebDavTicket] GetDetails status: %d", resp.StatusCode)
		return nil, fmt.Errorf("dirsize disk_usage returned status: %d", resp.StatusCode)
	}

	var data diskUsageResp
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return &model.StorageDetails{
		DiskUsage: model.DiskUsage{
			TotalSpace: data.Total,
			UsedSpace:  data.Used,
		},
	}, nil
}

func (d *WebDavTicket) queryDirSizes(ctx context.Context, dirPath string) map[string]int64 {
	if d.Address == "" {
		return nil
	}
	apiURL := strings.TrimRight(d.Address, "/") + "/dirsize-api/v1/query"
	payload, _ := json.Marshal(dirSizeQueryReq{DirPath: dirPath, Force: false})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(payload))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(d.Username, d.Password)

	client := d.httpClient(3 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		log.Warnf("[WebDavTicket] queryDirSizes error for %s: %v", dirPath, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warnf("[WebDavTicket] queryDirSizes status for %s: %d", dirPath, resp.StatusCode)
		return nil
	}

	var data dirSizeQueryResp
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		log.Warnf("[WebDavTicket] queryDirSizes decode error for %s: %v", dirPath, err)
		return nil
	}

	log.Infof("[WebDavTicket] queryDirSizes for %s: status=%s, children=%+v", dirPath, data.Status, data.DirectChildrenSizes)

	if (data.Status == "ready" || data.Status == "cooling_down") && data.DirectChildrenSizes != nil {
		return data.DirectChildrenSizes
	}
	return nil
}
