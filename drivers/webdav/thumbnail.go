package webdav

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/internal/stream"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	ffmpeg "github.com/u2takey/ffmpeg-go"
)

const (
	webDAVThumbType = "thumb"
	webDAVThumbExt  = ".jpg"
)

// thumbURL returns the normal signed OpenList thumbnail endpoint. The remote
// WebDAV URL is intentionally not exposed to the browser.
func thumbURL(ctx context.Context, reqPath string) string {
	endpoint := utils.EncodePath(path.Join("/d", reqPath), true)
	return fmt.Sprintf("%s%s?type=%s&sign=%s", apiURL(ctx), endpoint, webDAVThumbType, sign.Sign(reqPath))
}

func apiURL(ctx context.Context) string {
	api, _ := ctx.Value(conf.ApiUrlKey).(string)
	return api
}

func (d *WebDav) thumbLink(ctx context.Context, file model.Obj) (*model.Link, error) {
	if !d.Thumbnail || file.IsDir() {
		return nil, errors.New("webdav thumbnails are disabled")
	}

	fileType := utils.GetFileType(file.GetName())
	if fileType != conf.IMAGE && fileType != conf.VIDEO {
		return nil, errors.New("thumbnail is not supported for this file type")
	}
	if d.WebDAVAuthEnabled && d.WebDAVThumbnailPath != "" {
		thumbnailURL, err := d.thumbnailURL(ctx, file.GetPath(), file.GetPath())
		if err != nil {
			return nil, err
		}
		return &model.Link{URL: thumbnailURL}, nil
	}

	d.thumbMu.Lock()
	defer d.thumbMu.Unlock()

	cachePath := d.thumbCachePath(file)
	if cachePath != "" {
		if data, err := os.ReadFile(cachePath); err == nil {
			return thumbLinkFromBytes(data), nil
		}
	}

	// This check is deliberately strict. gowebdav.ReadStreamRange has a
	// compatibility fallback for servers returning 200, but thumbnails must
	// never turn into a full-file download.
	rangeSupported, err := d.client.SupportsRange(file.GetPath())
	if err != nil {
		return nil, err
	}
	if !rangeSupported {
		return nil, errors.New("webdav server does not support HTTP Range for thumbnail generation")
	}

	url, header, err := d.client.Link(file.GetPath())
	if err != nil {
		return nil, err
	}

	data, err := renderRemoteThumbnail(url, header, fileType, d.VideoThumbPos)
	if err != nil {
		return nil, err
	}
	if cachePath != "" {
		if err := writeThumbCache(cachePath, data); err != nil {
			return nil, err
		}
	}
	return thumbLinkFromBytes(data), nil
}

func (d *WebDav) thumbCachePath(file model.Obj) string {
	if d.ThumbCacheFolder == "" {
		return ""
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%d\x00%d\x00%s", file.GetPath(), file.ModTime().UnixNano(), file.GetSize(), d.VideoThumbPos)
	return filepath.Join(d.ThumbCacheFolder, hex.EncodeToString(h.Sum(nil))+webDAVThumbExt)
}

func writeThumbCache(cachePath string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(cachePath), ".thumb-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, cachePath)
}

func thumbLinkFromBytes(data []byte) *model.Link {
	reader := bytes.NewReader(data)
	return &model.Link{
		Header:        http.Header{"Content-Type": []string{"image/jpeg"}},
		RangeReader:   stream.GetRangeReaderFromMFile(int64(reader.Len()), reader),
		ContentLength: int64(reader.Len()),
	}
}

func renderRemoteThumbnail(url string, header http.Header, fileType int, videoThumbPos string) ([]byte, error) {
	inputArgs := ffmpeg.KwArgs{
		"seekable":   "1",
		"rw_timeout": "30000000",
	}
	if headerValue := ffmpegHeaders(header); headerValue != "" {
		inputArgs["headers"] = headerValue
	}

	if fileType == conf.VIDEO {
		probeJSON, err := ffmpeg.ProbeWithTimeout(url, 30_000_000_000, inputArgs)
		if err != nil {
			return nil, err
		}
		ss, err := snapshotPosition(probeJSON, videoThumbPos)
		if err != nil {
			return nil, err
		}
		inputArgs["ss"] = ss
	}

	output := bytes.NewBuffer(nil)
	stream := ffmpeg.Input(url, inputArgs).
		Output("pipe:", ffmpeg.KwArgs{
			"vframes": 1,
			"format":  "image2",
			"vcodec":  "mjpeg",
		}).
		GlobalArgs("-loglevel", "error").
		Silent(true).
		WithOutput(output, os.Stdout)
	if err := stream.Run(); err != nil {
		return nil, err
	}
	if output.Len() == 0 {
		return nil, errors.New("ffmpeg generated an empty thumbnail")
	}
	return output.Bytes(), nil
}

func ffmpegHeaders(header http.Header) string {
	var b strings.Builder
	for key, values := range header {
		for _, value := range values {
			b.WriteString(key)
			b.WriteString(": ")
			b.WriteString(strings.ReplaceAll(strings.ReplaceAll(value, "\r", ""), "\n", ""))
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

func snapshotPosition(probeJSON, position string) (string, error) {
	var probe struct {
		Format struct {
			Duration string `json:"duration"`
		} `json:"format"`
	}
	if err := json.Unmarshal([]byte(probeJSON), &probe); err != nil {
		return "", err
	}
	duration, err := strconv.ParseFloat(probe.Format.Duration, 64)
	if err != nil || duration < 0 {
		return "", errors.New("video duration is unavailable")
	}
	if position == "" {
		position = "20%"
	}
	if strings.HasSuffix(position, "%") {
		percentage, err := strconv.ParseFloat(strings.TrimSuffix(position, "%"), 64)
		if err != nil || percentage < 0 || percentage > 100 {
			return "", errors.New("invalid video thumbnail percentage")
		}
		return strconv.FormatFloat(duration*percentage/100, 'f', 6, 64), nil
	}
	seconds, err := strconv.ParseFloat(position, 64)
	if err != nil || seconds < 0 {
		return "", errors.New("invalid video thumbnail position")
	}
	if seconds > duration {
		seconds = duration
	}
	return strconv.FormatFloat(seconds, 'f', 6, 64), nil
}
